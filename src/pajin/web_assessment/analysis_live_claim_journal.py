"""Durable dual-identity claim journal for one live Web-analysis completion.

This module owns no model, Provider, target, Tool, Finding, Graph, report, or
retry authority.  It records a fail-closed, single-use coordination claim so a
later runtime can prove that one preparation and one authorization identity
were never recombined or replayed.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Final, Literal, Never, Self, cast
from weakref import WeakKeyDictionary

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.runtime.host_gate import host_work
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.supervision.invocation_journal import (
    SupervisorInvocationJournalError,
    _application_tables,
    _file_identity,
    _normalize_schema_sql,
    _readonly_connection_opened,
    _require_safe_path,
    _require_safe_sidecars,
    _write_transaction_opened,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
)

WEB_ANALYSIS_AUTHORIZATION_COORDINATE_API_VERSION: Final = (
    "pajin.dev/web-analysis-one-call-authorization-coordinate/v1alpha1"
)
WEB_ANALYSIS_LIVE_CLAIM_BINDING_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-claim-binding/v1alpha1"
)
WEB_ANALYSIS_LIVE_CLAIM_ENTRY_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-claim-journal-entry/v1alpha1"
)
WEB_ANALYSIS_LIVE_CLAIM_GATE_D_CONTEXT_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-claim-gate-d-context/v1alpha1"
)
WEB_ANALYSIS_LIVE_CLAIM_TERMINAL_PUBLICATION_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-claim-terminal-publication/v1alpha1"
)

# Version 1 never backed a permitted live dispatch.  Refuse it instead of
# mutating immutable audit state through an implicit in-place migration.
_SCHEMA_VERSION = 2
_APPLICATION_ID = 0x50415742  # ASCII "PAWB"
_BUSY_TIMEOUT_MS = 30_000
_MAX_BINDING_BYTES = 512 * 1024
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_OWNER_PATTERN = r"^[a-f0-9]{32}$"
_TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
_EXECUTION_ID_PATTERN = r"^exec_[a-f0-9]{32}$"
_LEASE_ID_PATTERN = r"^lease_[a-f0-9]{32}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]
_OwnerID = Annotated[str, Field(pattern=_OWNER_PATTERN)]
_Timestamp = Annotated[str, Field(pattern=_TIMESTAMP_PATTERN)]
_ExecutionID = Annotated[str, Field(pattern=_EXECUTION_ID_PATTERN)]
_LeaseID = Annotated[str, Field(pattern=_LEASE_ID_PATTERN)]
_RunID = Annotated[str, Field(pattern=_RUN_ID_PATTERN)]


class WebAnalysisLiveClaimJournalError(RuntimeError):
    """Raised when durable live-claim coordination fails closed."""


class WebAnalysisLiveClaimPhase(StrEnum):
    """Four durable phases required before a claim can become terminal."""

    RESERVATION = "reservation"
    LIVE_START = "live-start"
    PENDING_CLEANUP = "pending-cleanup"
    TERMINAL = "terminal"


class WebAnalysisLiveClaimPendingOutcome(StrEnum):
    """Conservative outcome known when cleanup becomes mandatory."""

    NOT_DISPATCHED = "not-dispatched"
    SUCCESS_OBSERVED = "success-observed"
    FAILURE_OBSERVED = "failure-observed"
    OUTCOME_UNKNOWN = "outcome-unknown"


class WebAnalysisLiveClaimTerminalDisposition(StrEnum):
    """Final disposition sealed only after cleanup and absence verification."""

    SUCCESS = "success"
    FAILURE = "failure"
    ABANDONED = "abandoned"


def _digest(domain: str, value: object) -> str:
    payload = canonical_json_bytes(
        value,
        label="Web analysis live claim identity",
        max_bytes=_MAX_BINDING_BYTES,
    )
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + payload).hexdigest()


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis live claim authority markers must be literal false")
    return False


class _FrozenClaimModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class WebAnalysisOneCallAuthorizationCoordinate(_FrozenClaimModel):
    """Unverified identity coordinate; Gate C must verify the real authorization.

    The coordinate deliberately carries no invocation authority.  Its stable
    identity is issuer/key plus nonce, while ``authorizationEnvelopeDigest``
    binds the exact future authorization bytes.  A differently signed or
    modified envelope with the same nonce therefore still collides durably.
    """

    api_version: Literal["pajin.dev/web-analysis-one-call-authorization-coordinate/v1alpha1"] = (
        Field(default=WEB_ANALYSIS_AUTHORIZATION_COORDINATE_API_VERSION, alias="apiVersion")
    )
    kind: Literal["WebAnalysisOneCallAuthorizationCoordinate"] = (
        "WebAnalysisOneCallAuthorizationCoordinate"
    )
    coordinate_id: str = Field(default="", alias="coordinateId", max_length=110)
    coordinate_digest: str = Field(default="", alias="coordinateDigest", max_length=64)
    authorization_identity: str = Field(default="", alias="authorizationIdentity", max_length=64)
    authorization_envelope_digest: _Sha256 = Field(alias="authorizationEnvelopeDigest")
    issuer: str = Field(min_length=1, max_length=200)
    key_id: str = Field(alias="keyId", min_length=1, max_length=200)
    nonce: str = Field(min_length=16, max_length=256)
    status: Literal["unverified-identity-coordinate-no-authority"] = (
        "unverified-identity-coordinate-no-authority"
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False, alias="modelInvocationAuthorized"
    )
    provider_dispatch_authorized: Literal[False] = Field(
        default=False, alias="providerDispatchAuthorized"
    )
    target_request_authorized: Literal[False] = Field(
        default=False, alias="targetRequestAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "model_invocation_authorized",
        "provider_dispatch_authorized",
        "target_request_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_coordinate(self) -> Self:
        identity = _digest(
            "pajin.web-analysis.authorization-identity/v1",
            {"issuer": self.issuer, "keyId": self.key_id, "nonce": self.nonce},
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"coordinate_id", "coordinate_digest", "authorization_identity"},
        )
        coordinate_digest = _digest(
            "pajin.web-analysis.authorization-coordinate/v1",
            {**material, "authorizationIdentity": identity},
        )
        coordinate_id = f"web-analysis-authorization-coordinate:{coordinate_digest}"
        if self.authorization_identity and self.authorization_identity != identity:
            raise ValueError("Authorization coordinate identity differs")
        if self.coordinate_digest and self.coordinate_digest != coordinate_digest:
            raise ValueError("Authorization coordinate digest differs")
        if self.coordinate_id and self.coordinate_id != coordinate_id:
            raise ValueError("Authorization coordinate ID differs")
        object.__setattr__(self, "authorization_identity", identity)
        object.__setattr__(self, "coordinate_digest", coordinate_digest)
        object.__setattr__(self, "coordinate_id", coordinate_id)
        return self


class WebAnalysisLiveClaimResourceLocator(_FrozenClaimModel):
    """Exact owned Docker resource names fixed before any live side effect."""

    resource_owner: _OwnerID = Field(alias="resourceOwner")
    runtime_container_name: str = Field(alias="runtimeContainerName", max_length=100)
    seed_container_name: str = Field(alias="seedContainerName", max_length=100)
    volume_name: str = Field(alias="volumeName", max_length=100)
    network_name: str = Field(alias="networkName", max_length=100)

    @model_validator(mode="after")
    def bind_names(self) -> Self:
        owner = self.resource_owner
        expected = (
            f"pajin-web-analysis-live-{owner}",
            f"pajin-web-analysis-live-seed-{owner}",
            f"pajin-web-analysis-live-model-{owner}",
            f"pajin-web-analysis-live-network-{owner}",
        )
        actual = (
            self.runtime_container_name,
            self.seed_container_name,
            self.volume_name,
            self.network_name,
        )
        if actual != expected:
            raise ValueError("Live claim resource names differ from their owner")
        return self


class WebAnalysisLiveClaimBinding(_FrozenClaimModel):
    """Immutable preparation, authorization, admission, and resource binding."""

    api_version: Literal["pajin.dev/web-analysis-live-claim-binding/v1alpha1"] = Field(
        default=WEB_ANALYSIS_LIVE_CLAIM_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisLiveClaimBinding"] = "WebAnalysisLiveClaimBinding"
    claim_id: str = Field(default="", alias="claimId", max_length=110)
    claim_digest: str = Field(default="", alias="claimDigest", max_length=64)
    admission_id: str = Field(alias="admissionId", min_length=1, max_length=110)
    admission_digest: _Sha256 = Field(alias="admissionDigest")
    preparation_identity: _Sha256 = Field(alias="preparationIdentity")
    preparation_run_id: str = Field(alias="preparationRunId", min_length=1, max_length=100)
    preparation_run_root_digest: _Sha256 = Field(alias="preparationRunRootDigest")
    preparation_index_digest: _Sha256 = Field(alias="preparationIndexDigest")
    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")
    authorization_identity: _Sha256 = Field(alias="authorizationIdentity")
    authorization_envelope_digest: _Sha256 = Field(alias="authorizationEnvelopeDigest")
    authorization_coordinate_digest: _Sha256 = Field(alias="authorizationCoordinateDigest")
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    compact_projection_digest: _Sha256 = Field(alias="compactProjectionDigest")
    response_schema_digest: _Sha256 = Field(alias="responseSchemaDigest")
    resources: WebAnalysisLiveClaimResourceLocator
    authorization_verified: Literal[False] = Field(default=False, alias="authorizationVerified")
    model_invocation_authorized: Literal[False] = Field(
        default=False, alias="modelInvocationAuthorized"
    )
    provider_dispatch_authorized: Literal[False] = Field(
        default=False, alias="providerDispatchAuthorized"
    )
    target_request_authorized: Literal[False] = Field(
        default=False, alias="targetRequestAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False, alias="automaticRedispatchAuthorized"
    )

    @field_validator(
        "authorization_verified",
        "model_invocation_authorized",
        "provider_dispatch_authorized",
        "target_request_authorized",
        "execution_authorized",
        "automatic_redispatch_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_claim(self) -> Self:
        core = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"claim_id", "claim_digest", "resources"},
        )
        core_digest = _digest("pajin.web-analysis.live-claim-core/v1", core)
        owner = core_digest[:32]
        expected_resources = WebAnalysisLiveClaimResourceLocator(
            resourceOwner=owner,
            runtimeContainerName=f"pajin-web-analysis-live-{owner}",
            seedContainerName=f"pajin-web-analysis-live-seed-{owner}",
            volumeName=f"pajin-web-analysis-live-model-{owner}",
            networkName=f"pajin-web-analysis-live-network-{owner}",
        )
        if self.resources != expected_resources:
            raise ValueError("Live claim resource locator differs from exact binding")
        digest = _digest(
            "pajin.web-analysis.live-claim-binding/v1",
            {**core, "resources": expected_resources.model_dump(mode="json", by_alias=True)},
        )
        claim_id = f"web-analysis-live-claim:{digest}"
        if self.claim_digest and self.claim_digest != digest:
            raise ValueError("Live claim digest differs")
        if self.claim_id and self.claim_id != claim_id:
            raise ValueError("Live claim ID differs")
        object.__setattr__(self, "claim_digest", digest)
        object.__setattr__(self, "claim_id", claim_id)
        return self


def build_web_analysis_live_claim_binding(
    *,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    authorization: WebAnalysisOneCallAuthorizationCoordinate,
) -> WebAnalysisLiveClaimBinding:
    """Build a non-authoritative exact claim binding from sealed coordinates."""

    if type(admission) is not PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
        raise WebAnalysisLiveClaimJournalError(
            "Live claim requires the exact prepared admission envelope"
        )
    if type(authorization) is not WebAnalysisOneCallAuthorizationCoordinate:
        raise WebAnalysisLiveClaimJournalError(
            "Live claim requires the exact authorization identity coordinate"
        )
    try:
        exact_admission = PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(
            admission.model_dump(mode="python", by_alias=True)
        )
        exact_authorization = WebAnalysisOneCallAuthorizationCoordinate.model_validate(
            authorization.model_dump(mode="python", by_alias=True)
        )
        core = {
            "apiVersion": WEB_ANALYSIS_LIVE_CLAIM_BINDING_API_VERSION,
            "kind": "WebAnalysisLiveClaimBinding",
            "admissionId": exact_admission.admission_id,
            "admissionDigest": exact_admission.admission_digest,
            "preparationIdentity": exact_admission.preparation_digest,
            "preparationRunId": exact_admission.preparation_run_id,
            "preparationRunRootDigest": exact_admission.preparation_run_root_digest,
            "preparationIndexDigest": exact_admission.preparation_index_digest,
            "liveRequestDigest": exact_admission.live_request_digest,
            "authorizationIdentity": exact_authorization.authorization_identity,
            "authorizationEnvelopeDigest": (exact_authorization.authorization_envelope_digest),
            "authorizationCoordinateDigest": exact_authorization.coordinate_digest,
            "capacityPinDigest": exact_admission.capacity_pin_digest,
            "transportPinDigest": exact_admission.transport_pin_digest,
            "providerRegistrationDigest": exact_admission.provider_registration_digest,
            "providerChatRequestDigest": exact_admission.provider_chat_request_digest,
            "compactProjectionDigest": exact_admission.compact_projection_digest,
            "responseSchemaDigest": exact_admission.response_schema_digest,
            "authorizationVerified": False,
            "modelInvocationAuthorized": False,
            "providerDispatchAuthorized": False,
            "targetRequestAuthorized": False,
            "executionAuthorized": False,
            "automaticRedispatchAuthorized": False,
        }
        owner = _digest("pajin.web-analysis.live-claim-core/v1", core)[:32]
        return WebAnalysisLiveClaimBinding.model_validate(
            {
                **core,
                "claimId": "",
                "claimDigest": "",
                "resources": {
                    "resourceOwner": owner,
                    "runtimeContainerName": f"pajin-web-analysis-live-{owner}",
                    "seedContainerName": f"pajin-web-analysis-live-seed-{owner}",
                    "volumeName": f"pajin-web-analysis-live-model-{owner}",
                    "networkName": f"pajin-web-analysis-live-network-{owner}",
                },
            }
        )
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError("Live claim binding failed closed") from exc


class WebAnalysisLiveClaimJournalEntry(_FrozenClaimModel):
    """Audit-only projection of one durable claim; never a dispatch authority."""

    api_version: Literal["pajin.dev/web-analysis-live-claim-journal-entry/v1alpha1"] = Field(
        default=WEB_ANALYSIS_LIVE_CLAIM_ENTRY_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisLiveClaimJournalEntry"] = "WebAnalysisLiveClaimJournalEntry"
    binding: WebAnalysisLiveClaimBinding
    phase: WebAnalysisLiveClaimPhase
    reserved_at: _Timestamp = Field(alias="reservedAt")
    live_started_at: _Timestamp | None = Field(default=None, alias="liveStartedAt")
    dispatch_started_at: _Timestamp | None = Field(default=None, alias="dispatchStartedAt")
    pending_cleanup_at: _Timestamp | None = Field(default=None, alias="pendingCleanupAt")
    terminal_at: _Timestamp | None = Field(default=None, alias="terminalAt")
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None = Field(
        default=None, alias="pendingOutcome"
    )
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None = Field(
        default=None, alias="terminalDisposition"
    )
    cleanup_result_digest: _Sha256 | None = Field(default=None, alias="cleanupResultDigest")
    resource_absence_digest: _Sha256 | None = Field(default=None, alias="resourceAbsenceDigest")
    terminal_receipt_digest: _Sha256 | None = Field(default=None, alias="terminalReceiptDigest")
    dispatch_count: Literal[0, 1] = Field(alias="dispatchCount")
    state_digest: _Sha256 = Field(alias="stateDigest")
    event_digests: tuple[_Sha256, ...] = Field(alias="eventDigests", min_length=1)
    reusable: Literal[False] = False
    model_invocation_authorized: Literal[False] = Field(
        default=False, alias="modelInvocationAuthorized"
    )
    provider_dispatch_authorized: Literal[False] = Field(
        default=False, alias="providerDispatchAuthorized"
    )
    target_request_authorized: Literal[False] = Field(
        default=False, alias="targetRequestAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False, alias="automaticRedispatchAuthorized"
    )

    @field_validator(
        "reusable",
        "model_invocation_authorized",
        "provider_dispatch_authorized",
        "target_request_authorized",
        "execution_authorized",
        "automatic_redispatch_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def verify_state(self) -> Self:
        expected = _state_digest(
            binding_digest=self.binding.claim_digest,
            phase=self.phase,
            reserved_at=self.reserved_at,
            live_started_at=self.live_started_at,
            dispatch_started_at=self.dispatch_started_at,
            pending_cleanup_at=self.pending_cleanup_at,
            terminal_at=self.terminal_at,
            pending_outcome=self.pending_outcome,
            terminal_disposition=self.terminal_disposition,
            cleanup_result_digest=self.cleanup_result_digest,
            resource_absence_digest=self.resource_absence_digest,
            terminal_receipt_digest=self.terminal_receipt_digest,
            dispatch_count=self.dispatch_count,
        )
        if self.state_digest != expected:
            raise ValueError("Live claim state digest differs")
        _require_phase_shape(self)
        return self


class WebAnalysisLiveClaimGateDContext(_FrozenClaimModel):
    """Durable Gate-D evidence recorded before the one dispatch marker.

    The initial authorization evidence is written atomically with reservation.
    The optional group is intentionally all-or-none: once present it proves the
    exact re-verification and transport coordinates known before the durable
    dispatch slot was consumed.  This projection is audit-only and conveys no
    execution or redispatch authority.
    """

    api_version: Literal["pajin.dev/web-analysis-live-claim-gate-d-context/v1alpha1"] = Field(
        default=WEB_ANALYSIS_LIVE_CLAIM_GATE_D_CONTEXT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisLiveClaimGateDContext"] = "WebAnalysisLiveClaimGateDContext"
    claim_id: str = Field(alias="claimId", min_length=1, max_length=110)
    claim_digest: _Sha256 = Field(alias="claimDigest")
    initial_authorization_verification_digest: _Sha256 = Field(
        alias="initialAuthorizationVerificationDigest"
    )
    initial_authorization_evaluated_at: _Timestamp = Field(alias="initialAuthorizationEvaluatedAt")
    initial_authorization_expires_at: _Timestamp = Field(alias="initialAuthorizationExpiresAt")
    pre_dispatch_authorization_verification_digest: _Sha256 | None = Field(
        default=None,
        alias="preDispatchAuthorizationVerificationDigest",
    )
    pre_dispatch_authorization_evaluated_at: _Timestamp | None = Field(
        default=None,
        alias="preDispatchAuthorizationEvaluatedAt",
    )
    pre_dispatch_authorization_expires_at: _Timestamp | None = Field(
        default=None,
        alias="preDispatchAuthorizationExpiresAt",
    )
    provider_route_attestation_digest: _Sha256 | None = Field(
        default=None,
        alias="providerRouteAttestationDigest",
    )
    transport_execution_id: _ExecutionID | None = Field(
        default=None,
        alias="transportExecutionId",
    )
    lease_ids: tuple[_LeaseID, ...] | None = Field(
        default=None,
        alias="leaseIds",
        max_length=1,
    )
    worker_context_digest: _Sha256 | None = Field(
        default=None,
        alias="workerContextDigest",
    )
    job_metadata_digest: _Sha256 | None = Field(
        default=None,
        alias="jobMetadataDigest",
    )
    transport_binding_digest: _Sha256 | None = Field(
        default=None,
        alias="transportBindingDigest",
    )
    context_digest: str = Field(default="", alias="contextDigest", max_length=64)
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    provider_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="providerDispatchAuthorized",
    )
    target_request_authorized: Literal[False] = Field(
        default=False,
        alias="targetRequestAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )

    @field_validator(
        "model_invocation_authorized",
        "provider_dispatch_authorized",
        "target_request_authorized",
        "execution_authorized",
        "automatic_redispatch_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator(
        "initial_authorization_evaluated_at",
        "initial_authorization_expires_at",
        "pre_dispatch_authorization_evaluated_at",
        "pre_dispatch_authorization_expires_at",
    )
    @classmethod
    def require_canonical_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            _validate_timestamp(value, field="Gate-D authorization evaluation timestamp")
        except WebAnalysisLiveClaimJournalError as exc:
            raise ValueError("Gate-D authorization evaluation timestamp is invalid") from exc
        return value

    @model_validator(mode="after")
    def bind_context(self) -> Self:
        if self.claim_id != f"web-analysis-live-claim:{self.claim_digest}":
            raise ValueError("Gate-D context claim identity differs")
        optional_values = (
            self.pre_dispatch_authorization_verification_digest,
            self.pre_dispatch_authorization_evaluated_at,
            self.pre_dispatch_authorization_expires_at,
            self.provider_route_attestation_digest,
            self.transport_execution_id,
            self.lease_ids,
            self.worker_context_digest,
            self.job_metadata_digest,
            self.transport_binding_digest,
        )
        present = tuple(value is not None for value in optional_values)
        if any(present) and not all(present):
            raise ValueError("Gate-D pre-dispatch context must be all present or all absent")
        initial = _parse_timestamp(self.initial_authorization_evaluated_at)
        initial_expiry = _parse_timestamp(self.initial_authorization_expires_at)
        if initial >= initial_expiry:
            raise ValueError("Gate-D initial authorization is not active")
        if self.pre_dispatch_authorization_evaluated_at is not None:
            if self.lease_ids is None or len(self.lease_ids) != 1:
                raise ValueError("Gate-D pre-dispatch context requires exactly one lease")
            pre_dispatch = _parse_timestamp(self.pre_dispatch_authorization_evaluated_at)
            pre_dispatch_expiry = _parse_timestamp(
                cast(str, self.pre_dispatch_authorization_expires_at)
            )
            if pre_dispatch <= initial:
                raise ValueError(
                    "Gate-D pre-dispatch verification must follow initial verification"
                )
            if pre_dispatch >= pre_dispatch_expiry:
                raise ValueError("Gate-D pre-dispatch authorization is not active")
            if pre_dispatch_expiry != initial_expiry:
                raise ValueError("Gate-D pre-dispatch expiry differs from initial authorization")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"context_digest"},
        )
        digest = _digest("pajin.web-analysis.live-claim-gate-d-context/v1", material)
        if self.context_digest and self.context_digest != digest:
            raise ValueError("Gate-D context digest differs")
        object.__setattr__(self, "context_digest", digest)
        return self


class WebAnalysisLiveClaimTerminalPublication(_FrozenClaimModel):
    """Durable same-publication intent and optional sealed-root anchor.

    The intent is committed before the deterministic Run may be created.  A
    sealed root is attached by a one-way CAS only after the exact Run has been
    strict-loaded.  This closes both crash windows without granting permission
    to publish a second receipt or redispatch.
    """

    api_version: Literal["pajin.dev/web-analysis-live-claim-terminal-publication/v1alpha1"] = Field(
        default=WEB_ANALYSIS_LIVE_CLAIM_TERMINAL_PUBLICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisLiveClaimTerminalPublication"] = (
        "WebAnalysisLiveClaimTerminalPublication"
    )
    claim_id: str = Field(alias="claimId", min_length=1, max_length=110)
    claim_digest: _Sha256 = Field(alias="claimDigest")
    pending_claim_state_digest: _Sha256 = Field(alias="pendingClaimStateDigest")
    output_root: str = Field(alias="outputRoot", min_length=1, max_length=4096)
    run_path: str = Field(alias="runPath", min_length=1, max_length=4096)
    run_id: _RunID = Field(alias="runId")
    receipt_digest: _Sha256 = Field(alias="receiptDigest")
    cleanup_result_digest: _Sha256 = Field(alias="cleanupResultDigest")
    resource_absence_digest: _Sha256 = Field(alias="resourceAbsenceDigest")
    intended_terminal_disposition: WebAnalysisLiveClaimTerminalDisposition = Field(
        alias="intendedTerminalDisposition"
    )
    live_attestation_digest: _Sha256 | None = Field(
        default=None,
        alias="liveAttestationDigest",
    )
    intent_digest: str = Field(default="", alias="intentDigest", max_length=64)
    root_digest: _Sha256 | None = Field(default=None, alias="rootDigest")
    publication_digest: str | None = Field(
        default=None,
        alias="publicationDigest",
        max_length=64,
    )
    reusable: Literal[False] = False
    provider_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="providerDispatchAuthorized",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )

    @field_validator(
        "reusable",
        "provider_dispatch_authorized",
        "automatic_redispatch_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("output_root", "run_path")
    @classmethod
    def require_canonical_absolute_path(cls, value: str) -> str:
        if "\x00" in value or value != os.path.abspath(value):
            raise ValueError("Terminal publication path must be canonical and absolute")
        return value

    @model_validator(mode="after")
    def bind_publication(self) -> Self:
        if self.claim_id != f"web-analysis-live-claim:{self.claim_digest}":
            raise ValueError("Terminal publication claim identity differs")
        output_root = Path(self.output_root)
        run_path = Path(self.run_path)
        if run_path == output_root or output_root not in run_path.parents:
            raise ValueError("Terminal publication Run is outside its output root")
        if run_path.name != self.run_id:
            raise ValueError("Terminal publication Run path differs from its Run identity")
        intent_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"intent_digest", "root_digest", "publication_digest"},
        )
        intent_digest = _digest(
            "pajin.web-analysis.live-claim-terminal-publication-intent/v1",
            intent_material,
        )
        if self.intent_digest and self.intent_digest != intent_digest:
            raise ValueError("Terminal publication intent digest differs")
        object.__setattr__(self, "intent_digest", intent_digest)
        if (self.root_digest is None) != (self.publication_digest is None):
            raise ValueError("Terminal publication root anchor must be all present or absent")
        if self.root_digest is not None:
            publication_digest = _digest(
                "pajin.web-analysis.live-claim-terminal-publication-anchor/v1",
                {"intentDigest": intent_digest, "rootDigest": self.root_digest},
            )
            if self.publication_digest not in {"", publication_digest}:
                raise ValueError("Terminal publication anchor digest differs")
            object.__setattr__(self, "publication_digest", publication_digest)
        return self


@dataclass(slots=True)
class _ClaimHandleState:
    entry: WebAnalysisLiveClaimJournalEntry
    authority: object
    consumed: bool = False


class _ClaimHandle:
    __slots__ = ("__weakref__",)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Live claim handles can only be issued by the winning journal transaction")

    @property
    def entry(self) -> WebAnalysisLiveClaimJournalEntry:
        """Return an audit projection without transferring the handle authority."""

        return _claim_handle_state(self).entry

    def _require(self, authority: object) -> WebAnalysisLiveClaimJournalEntry:
        state = _claim_handle_state(self)
        if state.authority is not authority or state.consumed:
            raise WebAnalysisLiveClaimJournalError("Live claim handle is foreign or consumed")
        return state.entry

    def _consume(self, authority: object) -> None:
        state = _claim_handle_state(self)
        if state.authority is not authority or state.consumed:
            raise WebAnalysisLiveClaimJournalError("Live claim handle is foreign or consumed")
        state.consumed = True

    def __copy__(self) -> Self:
        raise TypeError("Live claim handles cannot be copied")

    def __deepcopy__(self, memo: object) -> Self:
        del memo
        raise TypeError("Live claim handles cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("Live claim handles cannot be serialized")


class ReservedWebAnalysisLiveClaim(_ClaimHandle):
    """Store-local, one-use authority to enter live-start or pending-cleanup."""


class StartedWebAnalysisLiveClaim(_ClaimHandle):
    """Store-local, one-use authority to mark dispatch or pending-cleanup."""


class DispatchStartedWebAnalysisLiveClaim(_ClaimHandle):
    """Store-local, one-use authority to record the observed dispatch outcome."""


class VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate:
    """Non-serializable, store-local proof minted by the strict receipt loader."""

    __slots__ = ("__weakref__",)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "Verified terminal publication candidates can only be issued by the strict loader"
        )

    @property
    def claim_id(self) -> str:
        return _verified_terminal_publication_candidate_state(self)[0]

    @property
    def intent_digest(self) -> str:
        return _verified_terminal_publication_candidate_state(self)[1]

    @property
    def root_digest(self) -> str:
        return _verified_terminal_publication_candidate_state(self)[2]

    def __copy__(self) -> Self:
        raise TypeError("Verified terminal publication candidates cannot be copied")

    def __deepcopy__(self, memo: object) -> Self:
        del memo
        raise TypeError("Verified terminal publication candidates cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("Verified terminal publication candidates cannot be serialized")


_CLAIM_HANDLE_STATES: WeakKeyDictionary[_ClaimHandle, _ClaimHandleState] = WeakKeyDictionary()


def _issue_claim_handle[HandleT: _ClaimHandle](
    handle_type: type[HandleT],
    entry: WebAnalysisLiveClaimJournalEntry,
    authority: object,
) -> HandleT:
    handle = object.__new__(handle_type)
    _CLAIM_HANDLE_STATES[handle] = _ClaimHandleState(entry=entry, authority=authority)
    return handle


def _claim_handle_state(handle: _ClaimHandle) -> _ClaimHandleState:
    state = _CLAIM_HANDLE_STATES.get(handle)
    if state is None:
        raise WebAnalysisLiveClaimJournalError("Live claim handle was not journal-issued")
    return state


def _verified_terminal_publication_candidate_state(
    candidate: VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
) -> tuple[str, str, str]:
    from pajin.web_assessment.analysis_skill_compact_live_receipts import (
        _peek_verified_terminal_publication_candidate,
    )

    return _peek_verified_terminal_publication_candidate(candidate)


_METADATA_TABLE_SQL = """
    CREATE TABLE web_analysis_live_claim_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_CLAIMS_TABLE_SQL = """
    CREATE TABLE web_analysis_live_claims (
        claim_id TEXT PRIMARY KEY NOT NULL,
        claim_digest TEXT NOT NULL UNIQUE,
        admission_digest TEXT NOT NULL UNIQUE,
        preparation_identity TEXT NOT NULL UNIQUE,
        authorization_identity TEXT NOT NULL UNIQUE,
        authorization_envelope_digest TEXT NOT NULL,
        resource_owner TEXT NOT NULL UNIQUE,
        canonical_binding BLOB NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN (
            'reservation', 'live-start', 'pending-cleanup', 'terminal'
        )),
        reserved_at TEXT NOT NULL,
        live_started_at TEXT,
        dispatch_started_at TEXT,
        pending_cleanup_at TEXT,
        terminal_at TEXT,
        pending_outcome TEXT CHECK (pending_outcome IS NULL OR pending_outcome IN (
            'not-dispatched', 'success-observed', 'failure-observed', 'outcome-unknown'
        )),
        terminal_disposition TEXT CHECK (
            terminal_disposition IS NULL OR terminal_disposition IN (
                'success', 'failure', 'abandoned'
            )
        ),
        cleanup_result_digest TEXT,
        resource_absence_digest TEXT,
        terminal_receipt_digest TEXT,
        dispatch_count INTEGER NOT NULL CHECK (dispatch_count IN (0, 1)),
        state_digest TEXT NOT NULL,
        CHECK (
            (phase = 'reservation'
             AND live_started_at IS NULL AND dispatch_started_at IS NULL
             AND pending_cleanup_at IS NULL AND terminal_at IS NULL
             AND pending_outcome IS NULL AND terminal_disposition IS NULL
             AND cleanup_result_digest IS NULL AND resource_absence_digest IS NULL
             AND terminal_receipt_digest IS NULL AND dispatch_count = 0)
            OR
            (phase = 'live-start'
             AND live_started_at IS NOT NULL AND pending_cleanup_at IS NULL
             AND terminal_at IS NULL AND pending_outcome IS NULL
             AND terminal_disposition IS NULL AND cleanup_result_digest IS NULL
             AND resource_absence_digest IS NULL AND terminal_receipt_digest IS NULL
             AND ((dispatch_count = 0 AND dispatch_started_at IS NULL)
                  OR (dispatch_count = 1 AND dispatch_started_at IS NOT NULL)))
            OR
            (phase = 'pending-cleanup'
             AND pending_cleanup_at IS NOT NULL AND terminal_at IS NULL
             AND pending_outcome IS NOT NULL AND terminal_disposition IS NULL
             AND cleanup_result_digest IS NULL AND resource_absence_digest IS NULL
             AND terminal_receipt_digest IS NULL
             AND ((dispatch_count = 0 AND dispatch_started_at IS NULL)
                  OR (dispatch_count = 1 AND dispatch_started_at IS NOT NULL)))
            OR
            (phase = 'terminal'
             AND pending_cleanup_at IS NOT NULL AND terminal_at IS NOT NULL
             AND pending_outcome IS NOT NULL AND terminal_disposition IS NOT NULL
             AND cleanup_result_digest IS NOT NULL
             AND resource_absence_digest IS NOT NULL
             AND terminal_receipt_digest IS NOT NULL
             AND ((dispatch_count = 0 AND dispatch_started_at IS NULL)
                  OR (dispatch_count = 1 AND dispatch_started_at IS NOT NULL))
             AND (terminal_disposition != 'success'
                  OR (dispatch_count = 1 AND pending_outcome = 'success-observed')))
        )
    ) STRICT
    """
_GATE_D_CONTEXTS_TABLE_SQL = """
    CREATE TABLE web_analysis_live_claim_gate_d_contexts (
        claim_id TEXT PRIMARY KEY NOT NULL
            REFERENCES web_analysis_live_claims(claim_id),
        claim_digest TEXT NOT NULL UNIQUE,
        initial_authorization_verification_digest TEXT NOT NULL,
        initial_authorization_evaluated_at TEXT NOT NULL,
        initial_authorization_expires_at TEXT NOT NULL,
        pre_dispatch_authorization_verification_digest TEXT,
        pre_dispatch_authorization_evaluated_at TEXT,
        pre_dispatch_authorization_expires_at TEXT,
        provider_route_attestation_digest TEXT,
        transport_execution_id TEXT,
        lease_ids_json BLOB,
        worker_context_digest TEXT,
        job_metadata_digest TEXT,
        transport_binding_digest TEXT,
        context_digest TEXT NOT NULL UNIQUE,
        CHECK (
            (pre_dispatch_authorization_verification_digest IS NULL
             AND pre_dispatch_authorization_evaluated_at IS NULL
             AND pre_dispatch_authorization_expires_at IS NULL
             AND provider_route_attestation_digest IS NULL
             AND transport_execution_id IS NULL
             AND lease_ids_json IS NULL
             AND worker_context_digest IS NULL
             AND job_metadata_digest IS NULL
             AND transport_binding_digest IS NULL)
            OR
            (pre_dispatch_authorization_verification_digest IS NOT NULL
             AND pre_dispatch_authorization_evaluated_at IS NOT NULL
             AND pre_dispatch_authorization_expires_at IS NOT NULL
             AND provider_route_attestation_digest IS NOT NULL
             AND transport_execution_id IS NOT NULL
             AND lease_ids_json IS NOT NULL
             AND json_array_length(CAST(lease_ids_json AS TEXT)) = 1
             AND worker_context_digest IS NOT NULL
             AND job_metadata_digest IS NOT NULL
             AND transport_binding_digest IS NOT NULL)
        )
    ) STRICT
    """
_TERMINAL_PUBLICATIONS_TABLE_SQL = """
    CREATE TABLE web_analysis_live_claim_terminal_publications (
        claim_id TEXT PRIMARY KEY NOT NULL
            REFERENCES web_analysis_live_claims(claim_id),
        claim_digest TEXT NOT NULL UNIQUE,
        pending_claim_state_digest TEXT NOT NULL UNIQUE,
        output_root TEXT NOT NULL,
        run_path TEXT NOT NULL UNIQUE,
        run_id TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        cleanup_result_digest TEXT NOT NULL,
        resource_absence_digest TEXT NOT NULL,
        intended_terminal_disposition TEXT NOT NULL CHECK (
            intended_terminal_disposition IN ('success', 'failure', 'abandoned')
        ),
        live_attestation_digest TEXT,
        intent_digest TEXT NOT NULL UNIQUE,
        root_digest TEXT,
        publication_digest TEXT UNIQUE,
        CHECK (
            (root_digest IS NULL AND publication_digest IS NULL)
            OR (root_digest IS NOT NULL AND publication_digest IS NOT NULL)
        )
    ) STRICT
    """
_EVENTS_TABLE_SQL = """
    CREATE TABLE web_analysis_live_claim_events (
        event_id INTEGER PRIMARY KEY,
        claim_id TEXT NOT NULL REFERENCES web_analysis_live_claims(claim_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
        event_type TEXT NOT NULL CHECK (event_type IN (
            'reservation', 'live-start', 'dispatch-started',
            'pending-cleanup', 'cleanup-failed', 'terminal'
        )),
        from_phase TEXT CHECK (from_phase IS NULL OR from_phase IN (
            'reservation', 'live-start', 'pending-cleanup'
        )),
        to_phase TEXT NOT NULL CHECK (to_phase IN (
            'reservation', 'live-start', 'pending-cleanup', 'terminal'
        )),
        occurred_at TEXT NOT NULL,
        pending_outcome TEXT,
        terminal_disposition TEXT,
        evidence_digest TEXT,
        previous_event_digest TEXT,
        event_digest TEXT NOT NULL,
        UNIQUE(claim_id, ordinal)
    ) STRICT
    """
_EVENTS_INDEX_SQL = (
    "CREATE INDEX web_analysis_live_claim_events_claim_idx "
    "ON web_analysis_live_claim_events(claim_id, ordinal)"
)
_METADATA_NO_UPDATE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_metadata_no_update
    BEFORE UPDATE ON web_analysis_live_claim_metadata
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim metadata is immutable');
    END
    """
_METADATA_NO_DELETE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_metadata_no_delete
    BEFORE DELETE ON web_analysis_live_claim_metadata
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim metadata is immutable');
    END
    """
_METADATA_NO_REPLACE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_metadata_no_replace
    BEFORE INSERT ON web_analysis_live_claim_metadata
    WHEN EXISTS (
        SELECT 1 FROM web_analysis_live_claim_metadata WHERE key = NEW.key
    )
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim metadata cannot be replaced');
    END
    """
_CLAIMS_IMMUTABLE_SQL = """
    CREATE TRIGGER web_analysis_live_claims_immutable
    BEFORE UPDATE OF
        claim_id, claim_digest, admission_digest, preparation_identity,
        authorization_identity, authorization_envelope_digest, resource_owner,
        canonical_binding, reserved_at
    ON web_analysis_live_claims
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim binding is immutable');
    END
    """
_CLAIMS_NO_DELETE_SQL = """
    CREATE TRIGGER web_analysis_live_claims_no_delete
    BEFORE DELETE ON web_analysis_live_claims
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claims are append-only');
    END
    """
_CLAIMS_NO_REPLACE_SQL = """
    CREATE TRIGGER web_analysis_live_claims_no_replace
    BEFORE INSERT ON web_analysis_live_claims
    WHEN EXISTS (
        SELECT 1 FROM web_analysis_live_claims
        WHERE claim_id = NEW.claim_id OR claim_digest = NEW.claim_digest
           OR admission_digest = NEW.admission_digest
           OR preparation_identity = NEW.preparation_identity
           OR authorization_identity = NEW.authorization_identity
           OR resource_owner = NEW.resource_owner
    )
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claims cannot be replaced');
    END
    """
_CLAIMS_TRANSITION_SQL = """
    CREATE TRIGGER web_analysis_live_claims_transition
    BEFORE UPDATE ON web_analysis_live_claims
    WHEN NOT (
        (OLD.phase = 'reservation' AND NEW.phase = 'live-start')
        OR (OLD.phase = 'reservation' AND NEW.phase = 'pending-cleanup')
        OR (OLD.phase = 'live-start' AND NEW.phase = 'pending-cleanup')
        OR (OLD.phase = 'pending-cleanup' AND NEW.phase = 'terminal'
            AND (
                NOT EXISTS (
                    SELECT 1 FROM web_analysis_live_claim_gate_d_contexts AS context
                    WHERE context.claim_id = OLD.claim_id
                )
                OR EXISTS (
                    SELECT 1
                    FROM web_analysis_live_claim_terminal_publications AS publication
                    WHERE publication.claim_id = OLD.claim_id
                      AND publication.claim_digest = OLD.claim_digest
                      AND publication.pending_claim_state_digest = OLD.state_digest
                      AND publication.root_digest IS NOT NULL
                      AND publication.publication_digest IS NOT NULL
                      AND publication.receipt_digest = NEW.terminal_receipt_digest
                      AND publication.cleanup_result_digest = NEW.cleanup_result_digest
                      AND publication.resource_absence_digest = NEW.resource_absence_digest
                      AND publication.intended_terminal_disposition
                          = NEW.terminal_disposition
                )
            ))
        OR (OLD.phase = 'live-start' AND NEW.phase = 'live-start'
            AND OLD.dispatch_count = 0 AND NEW.dispatch_count = 1
            AND OLD.dispatch_started_at IS NULL
            AND NEW.dispatch_started_at IS NOT NULL
            AND (
                NOT EXISTS (
                    SELECT 1 FROM web_analysis_live_claim_gate_d_contexts AS context
                    WHERE context.claim_id = OLD.claim_id
                )
                OR EXISTS (
                    SELECT 1 FROM web_analysis_live_claim_gate_d_contexts AS context
                    WHERE context.claim_id = OLD.claim_id
                      AND context.pre_dispatch_authorization_verification_digest
                          IS NOT NULL
                      AND context.pre_dispatch_authorization_evaluated_at IS NOT NULL
                      AND context.pre_dispatch_authorization_expires_at IS NOT NULL
                      AND context.provider_route_attestation_digest IS NOT NULL
                      AND NEW.dispatch_started_at
                          < context.pre_dispatch_authorization_expires_at
                      AND context.transport_execution_id IS NOT NULL
                      AND context.lease_ids_json IS NOT NULL
                      AND json_array_length(CAST(context.lease_ids_json AS TEXT)) = 1
                      AND context.worker_context_digest IS NOT NULL
                      AND context.job_metadata_digest IS NOT NULL
                      AND context.transport_binding_digest IS NOT NULL
                )
            ))
    )
    BEGIN
        SELECT RAISE(ABORT, 'invalid Web analysis live claim transition');
    END
    """
_GATE_D_CONTEXTS_IMMUTABLE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_gate_d_contexts_immutable
    BEFORE UPDATE OF
        claim_id, claim_digest, initial_authorization_verification_digest,
        initial_authorization_evaluated_at, initial_authorization_expires_at
    ON web_analysis_live_claim_gate_d_contexts
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis Gate-D initial context is immutable');
    END
    """
_GATE_D_CONTEXTS_TRANSITION_SQL = """
    CREATE TRIGGER web_analysis_live_claim_gate_d_contexts_transition
    BEFORE UPDATE ON web_analysis_live_claim_gate_d_contexts
    WHEN NOT (
        OLD.pre_dispatch_authorization_verification_digest IS NULL
        AND OLD.pre_dispatch_authorization_evaluated_at IS NULL
        AND OLD.pre_dispatch_authorization_expires_at IS NULL
        AND OLD.provider_route_attestation_digest IS NULL
        AND OLD.transport_execution_id IS NULL
        AND OLD.lease_ids_json IS NULL
        AND OLD.worker_context_digest IS NULL
        AND OLD.job_metadata_digest IS NULL
        AND OLD.transport_binding_digest IS NULL
        AND NEW.pre_dispatch_authorization_verification_digest IS NOT NULL
        AND NEW.pre_dispatch_authorization_evaluated_at IS NOT NULL
        AND NEW.pre_dispatch_authorization_expires_at IS NOT NULL
        AND NEW.provider_route_attestation_digest IS NOT NULL
        AND NEW.pre_dispatch_authorization_expires_at
            = OLD.initial_authorization_expires_at
        AND NEW.transport_execution_id IS NOT NULL
        AND NEW.lease_ids_json IS NOT NULL
        AND json_array_length(CAST(NEW.lease_ids_json AS TEXT)) = 1
        AND NEW.worker_context_digest IS NOT NULL
        AND NEW.job_metadata_digest IS NOT NULL
        AND NEW.transport_binding_digest IS NOT NULL
        AND NEW.context_digest != OLD.context_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'invalid Web analysis Gate-D context transition');
    END
    """
_GATE_D_CONTEXTS_NO_DELETE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_gate_d_contexts_no_delete
    BEFORE DELETE ON web_analysis_live_claim_gate_d_contexts
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis Gate-D contexts are append-only');
    END
    """
_GATE_D_CONTEXTS_NO_REPLACE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_gate_d_contexts_no_replace
    BEFORE INSERT ON web_analysis_live_claim_gate_d_contexts
    WHEN EXISTS (
        SELECT 1 FROM web_analysis_live_claim_gate_d_contexts
        WHERE claim_id = NEW.claim_id OR claim_digest = NEW.claim_digest
           OR context_digest = NEW.context_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis Gate-D contexts cannot be replaced');
    END
    """
_TERMINAL_PUBLICATIONS_IMMUTABLE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_terminal_publications_immutable
    BEFORE UPDATE OF
        claim_id, claim_digest, pending_claim_state_digest, output_root,
        run_path, run_id, receipt_digest, cleanup_result_digest,
        resource_absence_digest, intended_terminal_disposition,
        live_attestation_digest, intent_digest
    ON web_analysis_live_claim_terminal_publications
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis terminal publication intent is immutable');
    END
    """
_TERMINAL_PUBLICATIONS_TRANSITION_SQL = """
    CREATE TRIGGER web_analysis_live_claim_terminal_publications_transition
    BEFORE UPDATE ON web_analysis_live_claim_terminal_publications
    WHEN NOT (
        OLD.root_digest IS NULL AND OLD.publication_digest IS NULL
        AND NEW.root_digest IS NOT NULL AND NEW.publication_digest IS NOT NULL
        AND NEW.publication_digest != OLD.intent_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'invalid Web analysis terminal publication transition');
    END
    """
_TERMINAL_PUBLICATIONS_NO_DELETE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_terminal_publications_no_delete
    BEFORE DELETE ON web_analysis_live_claim_terminal_publications
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis terminal publications are append-only');
    END
    """
_TERMINAL_PUBLICATIONS_NO_REPLACE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_terminal_publications_no_replace
    BEFORE INSERT ON web_analysis_live_claim_terminal_publications
    WHEN EXISTS (
        SELECT 1 FROM web_analysis_live_claim_terminal_publications
        WHERE claim_id = NEW.claim_id OR claim_digest = NEW.claim_digest
           OR pending_claim_state_digest = NEW.pending_claim_state_digest
           OR run_path = NEW.run_path OR receipt_digest = NEW.receipt_digest
           OR intent_digest = NEW.intent_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis terminal publications cannot be replaced');
    END
    """
_EVENTS_NO_UPDATE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_events_no_update
    BEFORE UPDATE ON web_analysis_live_claim_events
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim events are append-only');
    END
    """
_EVENTS_NO_DELETE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_events_no_delete
    BEFORE DELETE ON web_analysis_live_claim_events
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim events are append-only');
    END
    """
_EVENTS_NO_REPLACE_SQL = """
    CREATE TRIGGER web_analysis_live_claim_events_no_replace
    BEFORE INSERT ON web_analysis_live_claim_events
    WHEN EXISTS (
        SELECT 1 FROM web_analysis_live_claim_events
        WHERE event_id = NEW.event_id
           OR (claim_id = NEW.claim_id AND ordinal = NEW.ordinal)
    )
    BEGIN
        SELECT RAISE(ABORT, 'Web analysis live claim events cannot be replaced');
    END
    """

_SCHEMA_OBJECT_SQL = {
    ("table", "web_analysis_live_claim_metadata"): _METADATA_TABLE_SQL,
    ("table", "web_analysis_live_claims"): _CLAIMS_TABLE_SQL,
    ("table", "web_analysis_live_claim_gate_d_contexts"): _GATE_D_CONTEXTS_TABLE_SQL,
    (
        "table",
        "web_analysis_live_claim_terminal_publications",
    ): _TERMINAL_PUBLICATIONS_TABLE_SQL,
    ("table", "web_analysis_live_claim_events"): _EVENTS_TABLE_SQL,
    ("index", "web_analysis_live_claim_events_claim_idx"): _EVENTS_INDEX_SQL,
    ("trigger", "web_analysis_live_claim_metadata_no_update"): _METADATA_NO_UPDATE_SQL,
    ("trigger", "web_analysis_live_claim_metadata_no_delete"): _METADATA_NO_DELETE_SQL,
    ("trigger", "web_analysis_live_claim_metadata_no_replace"): _METADATA_NO_REPLACE_SQL,
    ("trigger", "web_analysis_live_claims_immutable"): _CLAIMS_IMMUTABLE_SQL,
    ("trigger", "web_analysis_live_claims_no_delete"): _CLAIMS_NO_DELETE_SQL,
    ("trigger", "web_analysis_live_claims_no_replace"): _CLAIMS_NO_REPLACE_SQL,
    ("trigger", "web_analysis_live_claims_transition"): _CLAIMS_TRANSITION_SQL,
    (
        "trigger",
        "web_analysis_live_claim_gate_d_contexts_immutable",
    ): _GATE_D_CONTEXTS_IMMUTABLE_SQL,
    (
        "trigger",
        "web_analysis_live_claim_gate_d_contexts_transition",
    ): _GATE_D_CONTEXTS_TRANSITION_SQL,
    (
        "trigger",
        "web_analysis_live_claim_gate_d_contexts_no_delete",
    ): _GATE_D_CONTEXTS_NO_DELETE_SQL,
    (
        "trigger",
        "web_analysis_live_claim_gate_d_contexts_no_replace",
    ): _GATE_D_CONTEXTS_NO_REPLACE_SQL,
    (
        "trigger",
        "web_analysis_live_claim_terminal_publications_immutable",
    ): _TERMINAL_PUBLICATIONS_IMMUTABLE_SQL,
    (
        "trigger",
        "web_analysis_live_claim_terminal_publications_transition",
    ): _TERMINAL_PUBLICATIONS_TRANSITION_SQL,
    (
        "trigger",
        "web_analysis_live_claim_terminal_publications_no_delete",
    ): _TERMINAL_PUBLICATIONS_NO_DELETE_SQL,
    (
        "trigger",
        "web_analysis_live_claim_terminal_publications_no_replace",
    ): _TERMINAL_PUBLICATIONS_NO_REPLACE_SQL,
    ("trigger", "web_analysis_live_claim_events_no_update"): _EVENTS_NO_UPDATE_SQL,
    ("trigger", "web_analysis_live_claim_events_no_delete"): _EVENTS_NO_DELETE_SQL,
    ("trigger", "web_analysis_live_claim_events_no_replace"): _EVENTS_NO_REPLACE_SQL,
}
_TABLES = frozenset(
    {
        "web_analysis_live_claim_metadata",
        "web_analysis_live_claims",
        "web_analysis_live_claim_gate_d_contexts",
        "web_analysis_live_claim_terminal_publications",
        "web_analysis_live_claim_events",
    }
)
_SCHEMA_DIGEST = sha256(
    canonical_json_bytes(
        {
            f"{kind}:{name}": _normalize_schema_sql(statement)
            for (kind, name), statement in sorted(_SCHEMA_OBJECT_SQL.items())
        },
        label="Web analysis live claim journal schema",
    )
).hexdigest()


class WebAnalysisLiveClaimJournal:
    """Crash-safe dual-identity CAS and cleanup recovery journal."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        expected_store_id: str | None = None,
        allow_create: bool = False,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self._clock = clock or (lambda: datetime.now(UTC))
        self._authority = object()
        try:
            if type(allow_create) is not bool:
                raise WebAnalysisLiveClaimJournalError("Journal creation setting must be a boolean")
            if expected_store_id is not None:
                _require_sha256(expected_store_id, label="expected live claim store identity")
            if not allow_create and expected_store_id is None:
                raise WebAnalysisLiveClaimJournalError(
                    "Opening a live claim journal requires its expected store identity"
                )
            if (
                allow_create
                and expected_store_id is None
                and self.path.exists()
                and self.path.stat().st_size > 0
            ):
                raise WebAnalysisLiveClaimJournalError(
                    "Opening an existing live claim journal requires its expected store identity"
                )
            with host_work():
                _initialize(self.path, allow_create=allow_create)
            with self._readonly() as connection:
                _validate_schema(connection)
                self._store_id = _metadata(connection)["store_id"]
            if expected_store_id is not None and self._store_id != expected_store_id:
                raise WebAnalysisLiveClaimJournalError("Live claim store identity differs")
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Live claim journal initialization failed closed"
            ) from exc

    @property
    def store_id(self) -> str:
        """Return the stable identity of this exact durable store."""

        return self._store_id

    def reserve(self, binding: WebAnalysisLiveClaimBinding) -> ReservedWebAnalysisLiveClaim:
        """Atomically consume both independent identities exactly once."""

        return self._reserve(binding, gate_d_initial_authorization=None)

    def reserve_with_gate_d_context(
        self,
        binding: WebAnalysisLiveClaimBinding,
        *,
        initial_authorization_verification_digest: str,
        initial_authorization_evaluated_at: datetime,
        initial_authorization_expires_at: datetime,
    ) -> ReservedWebAnalysisLiveClaim:
        """Reserve both identities and their initial Gate-D evidence atomically."""

        _require_sha256(
            initial_authorization_verification_digest,
            label="initial authorization verification digest",
        )
        evaluated_at = _timestamp_from_datetime(
            initial_authorization_evaluated_at,
            label="initial authorization evaluation time",
        )
        expires_at = _timestamp_from_datetime(
            initial_authorization_expires_at,
            label="initial authorization expiry time",
        )
        if _parse_timestamp(evaluated_at) >= _parse_timestamp(expires_at):
            raise WebAnalysisLiveClaimJournalError(
                "Initial authorization verification is not active"
            )
        return self._reserve(
            binding,
            gate_d_initial_authorization=(
                initial_authorization_verification_digest,
                evaluated_at,
                expires_at,
            ),
        )

    def _reserve(
        self,
        binding: WebAnalysisLiveClaimBinding,
        *,
        gate_d_initial_authorization: tuple[str, str, str] | None,
    ) -> ReservedWebAnalysisLiveClaim:
        try:
            exact = _canonical_binding(binding)
            reserved_at = self._now()
            gate_d_context: WebAnalysisLiveClaimGateDContext | None = None
            if gate_d_initial_authorization is not None:
                initial_digest, initial_evaluated_at, initial_expires_at = (
                    gate_d_initial_authorization
                )
                if _parse_timestamp(initial_evaluated_at) > _parse_timestamp(reserved_at):
                    raise WebAnalysisLiveClaimJournalError(
                        "Initial authorization verification follows reservation"
                    )
                if _parse_timestamp(reserved_at) >= _parse_timestamp(initial_expires_at):
                    raise WebAnalysisLiveClaimJournalError(
                        "Initial authorization expired before reservation"
                    )
                gate_d_context = WebAnalysisLiveClaimGateDContext(
                    claimId=exact.claim_id,
                    claimDigest=exact.claim_digest,
                    initialAuthorizationVerificationDigest=initial_digest,
                    initialAuthorizationEvaluatedAt=initial_evaluated_at,
                    initialAuthorizationExpiresAt=initial_expires_at,
                )
            state_digest = _state_digest(
                binding_digest=exact.claim_digest,
                phase=WebAnalysisLiveClaimPhase.RESERVATION,
                reserved_at=reserved_at,
                live_started_at=None,
                dispatch_started_at=None,
                pending_cleanup_at=None,
                terminal_at=None,
                pending_outcome=None,
                terminal_disposition=None,
                cleanup_result_digest=None,
                resource_absence_digest=None,
                terminal_receipt_digest=None,
                dispatch_count=0,
            )
            event_digest = _event_digest(
                claim_id=exact.claim_id,
                ordinal=1,
                event_type="reservation",
                from_phase=None,
                to_phase=WebAnalysisLiveClaimPhase.RESERVATION,
                occurred_at=reserved_at,
                pending_outcome=None,
                terminal_disposition=None,
                evidence_digest=None,
                previous_event_digest=None,
            )
            with self._write() as connection:
                self._validate_connection(connection)
                connection.execute(
                    """
                    INSERT INTO web_analysis_live_claims (
                        claim_id, claim_digest, admission_digest,
                        preparation_identity, authorization_identity,
                        authorization_envelope_digest, resource_owner,
                        canonical_binding, phase, reserved_at,
                        live_started_at, dispatch_started_at, pending_cleanup_at,
                        terminal_at, pending_outcome, terminal_disposition,
                        cleanup_result_digest, resource_absence_digest,
                        terminal_receipt_digest, dispatch_count, state_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL,
                              NULL, NULL, NULL, NULL, NULL, NULL, 0, ?)
                    """,
                    (
                        exact.claim_id,
                        exact.claim_digest,
                        exact.admission_digest,
                        exact.preparation_identity,
                        exact.authorization_identity,
                        exact.authorization_envelope_digest,
                        exact.resources.resource_owner,
                        sqlite3.Binary(_binding_bytes(exact)),
                        WebAnalysisLiveClaimPhase.RESERVATION.value,
                        reserved_at,
                        state_digest,
                    ),
                )
                if gate_d_context is not None:
                    _insert_gate_d_context(connection, gate_d_context)
                _insert_event(
                    connection,
                    claim_id=exact.claim_id,
                    ordinal=1,
                    event_type="reservation",
                    from_phase=None,
                    to_phase=WebAnalysisLiveClaimPhase.RESERVATION,
                    occurred_at=reserved_at,
                    pending_outcome=None,
                    terminal_disposition=None,
                    evidence_digest=None,
                    previous_event_digest=None,
                    event_digest=event_digest,
                )
                entry = _entry_from_row(connection, _load_claim(connection, exact.claim_id))
            return _issue_claim_handle(ReservedWebAnalysisLiveClaim, entry, self._authority)
        except sqlite3.IntegrityError as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Preparation or authorization identity was already consumed"
            ) from exc
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Live claim reservation failed closed; durable state requires recovery inspection"
            ) from exc

    def begin_live(self, handle: ReservedWebAnalysisLiveClaim) -> StartedWebAnalysisLiveClaim:
        """Commit live-start before the first owned-resource side effect."""

        expected = self._require_handle(
            handle, ReservedWebAnalysisLiveClaim, WebAnalysisLiveClaimPhase.RESERVATION
        )
        handle._consume(self._authority)
        entry = self._transition_to_live(expected)
        return _issue_claim_handle(StartedWebAnalysisLiveClaim, entry, self._authority)

    def record_gate_d_pre_dispatch_context(
        self,
        handle: StartedWebAnalysisLiveClaim,
        *,
        pre_dispatch_authorization_verification_digest: str,
        pre_dispatch_authorization_evaluated_at: datetime,
        pre_dispatch_authorization_expires_at: datetime,
        provider_route_attestation_digest: str,
        transport_execution_id: str,
        lease_ids: tuple[str, ...],
        worker_context_digest: str,
        job_metadata_digest: str,
        transport_binding_digest: str,
    ) -> StartedWebAnalysisLiveClaim:
        """Durably bind exact pre-marker evidence and reissue live authority."""

        _require_sha256(
            pre_dispatch_authorization_verification_digest,
            label="pre-dispatch authorization verification digest",
        )
        _require_sha256(
            provider_route_attestation_digest,
            label="provider route attestation digest",
        )
        evaluated_at = _timestamp_from_datetime(
            pre_dispatch_authorization_evaluated_at,
            label="pre-dispatch authorization evaluation time",
        )
        expires_at = _timestamp_from_datetime(
            pre_dispatch_authorization_expires_at,
            label="pre-dispatch authorization expiry time",
        )
        if _parse_timestamp(evaluated_at) >= _parse_timestamp(expires_at):
            raise WebAnalysisLiveClaimJournalError(
                "Pre-dispatch authorization verification is not active"
            )
        if (
            type(transport_execution_id) is not str
            or len(transport_execution_id) != 37
            or not transport_execution_id.startswith("exec_")
        ):
            raise WebAnalysisLiveClaimJournalError("Transport execution identity is invalid")
        exact_lease_ids = _canonical_lease_ids(lease_ids)
        for digest, label in (
            (worker_context_digest, "worker context digest"),
            (job_metadata_digest, "job metadata digest"),
            (transport_binding_digest, "transport binding digest"),
        ):
            _require_sha256(digest, label=label)
        expected = self._require_handle(
            handle,
            StartedWebAnalysisLiveClaim,
            WebAnalysisLiveClaimPhase.LIVE_START,
        )
        if expected.dispatch_count != 0:
            raise WebAnalysisLiveClaimJournalError(
                "Gate-D context must precede dispatch-slot consumption"
            )
        if expected.live_started_at is None or _parse_timestamp(evaluated_at) < _parse_timestamp(
            expected.live_started_at
        ):
            raise WebAnalysisLiveClaimJournalError(
                "Pre-dispatch authorization verification predates live-start"
            )
        exact_execution_id = f"exec_{expected.binding.resources.resource_owner}"
        if transport_execution_id != exact_execution_id:
            raise WebAnalysisLiveClaimJournalError(
                "Transport execution identity differs from the live claim"
            )
        handle._consume(self._authority)
        try:
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection,
                    _load_claim(connection, expected.binding.claim_id),
                )
                if current != expected or current.dispatch_count != 0:
                    raise WebAnalysisLiveClaimJournalError(
                        "Gate-D pre-dispatch claim differs from durable live state"
                    )
                initial = _gate_d_context_from_row(
                    _load_gate_d_context(connection, current.binding.claim_id),
                    binding=current.binding,
                )
                if initial.pre_dispatch_authorization_verification_digest is not None:
                    raise WebAnalysisLiveClaimJournalError(
                        "Gate-D pre-dispatch context was already recorded"
                    )
                updated = WebAnalysisLiveClaimGateDContext.model_validate(
                    {
                        **initial.model_dump(mode="python", by_alias=True),
                        "preDispatchAuthorizationVerificationDigest": (
                            pre_dispatch_authorization_verification_digest
                        ),
                        "preDispatchAuthorizationEvaluatedAt": evaluated_at,
                        "preDispatchAuthorizationExpiresAt": expires_at,
                        "providerRouteAttestationDigest": provider_route_attestation_digest,
                        "transportExecutionId": transport_execution_id,
                        "leaseIds": exact_lease_ids,
                        "workerContextDigest": worker_context_digest,
                        "jobMetadataDigest": job_metadata_digest,
                        "transportBindingDigest": transport_binding_digest,
                        "contextDigest": "",
                    }
                )
                cursor = connection.execute(
                    """
                    UPDATE web_analysis_live_claim_gate_d_contexts
                    SET pre_dispatch_authorization_verification_digest = ?,
                        pre_dispatch_authorization_evaluated_at = ?,
                        pre_dispatch_authorization_expires_at = ?,
                        provider_route_attestation_digest = ?,
                        transport_execution_id = ?, lease_ids_json = ?,
                        worker_context_digest = ?, job_metadata_digest = ?,
                        transport_binding_digest = ?, context_digest = ?
                    WHERE claim_id = ? AND context_digest = ?
                      AND pre_dispatch_authorization_verification_digest IS NULL
                      AND provider_route_attestation_digest IS NULL
                    """,
                    (
                        updated.pre_dispatch_authorization_verification_digest,
                        updated.pre_dispatch_authorization_evaluated_at,
                        updated.pre_dispatch_authorization_expires_at,
                        updated.provider_route_attestation_digest,
                        updated.transport_execution_id,
                        sqlite3.Binary(_lease_ids_bytes(exact_lease_ids)),
                        updated.worker_context_digest,
                        updated.job_metadata_digest,
                        updated.transport_binding_digest,
                        updated.context_digest,
                        current.binding.claim_id,
                        initial.context_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise WebAnalysisLiveClaimJournalError(
                        "Gate-D pre-dispatch context lost its atomic race"
                    )
                observed = _gate_d_context_from_row(
                    _load_gate_d_context(connection, current.binding.claim_id),
                    binding=current.binding,
                )
                if observed != updated:
                    raise WebAnalysisLiveClaimJournalError(
                        "Gate-D pre-dispatch context differs after recording"
                    )
            return _issue_claim_handle(StartedWebAnalysisLiveClaim, current, self._authority)
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Gate-D pre-dispatch context failed closed; durable state requires inspection"
            ) from exc

    def mark_dispatch_started(
        self, handle: StartedWebAnalysisLiveClaim
    ) -> DispatchStartedWebAnalysisLiveClaim:
        """Durably consume the one dispatch slot without performing dispatch."""

        expected = self._require_handle(
            handle, StartedWebAnalysisLiveClaim, WebAnalysisLiveClaimPhase.LIVE_START
        )
        if expected.dispatch_count != 0:
            raise WebAnalysisLiveClaimJournalError("Live claim dispatch slot was already consumed")
        handle._consume(self._authority)
        entry = self._mark_dispatch_started(expected)
        return _issue_claim_handle(DispatchStartedWebAnalysisLiveClaim, entry, self._authority)

    def mark_pending_cleanup(
        self,
        handle: (
            ReservedWebAnalysisLiveClaim
            | StartedWebAnalysisLiveClaim
            | DispatchStartedWebAnalysisLiveClaim
        ),
        *,
        outcome: WebAnalysisLiveClaimPendingOutcome,
    ) -> WebAnalysisLiveClaimJournalEntry:
        """Make a claimed identity non-reusable and cleanup-only."""

        if type(outcome) is not WebAnalysisLiveClaimPendingOutcome:
            raise WebAnalysisLiveClaimJournalError("Pending-cleanup outcome is invalid")
        if type(handle) is ReservedWebAnalysisLiveClaim:
            expected = self._require_handle(
                handle, ReservedWebAnalysisLiveClaim, WebAnalysisLiveClaimPhase.RESERVATION
            )
            if outcome not in {
                WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
            }:
                raise WebAnalysisLiveClaimJournalError(
                    "A reservation cannot record a dispatched outcome"
                )
        elif type(handle) is StartedWebAnalysisLiveClaim:
            expected = self._require_handle(
                handle, StartedWebAnalysisLiveClaim, WebAnalysisLiveClaimPhase.LIVE_START
            )
            if outcome not in {
                WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
            }:
                raise WebAnalysisLiveClaimJournalError(
                    "A pre-dispatch live claim cannot record a dispatched outcome"
                )
        elif type(handle) is DispatchStartedWebAnalysisLiveClaim:
            expected = self._require_handle(
                handle,
                DispatchStartedWebAnalysisLiveClaim,
                WebAnalysisLiveClaimPhase.LIVE_START,
            )
            if outcome is WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED:
                raise WebAnalysisLiveClaimJournalError(
                    "A consumed dispatch slot cannot become not-dispatched"
                )
        else:
            raise WebAnalysisLiveClaimJournalError("Pending-cleanup handle type is invalid")
        handle._consume(self._authority)
        entry = self._transition_to_pending(expected, outcome=outcome)
        return entry

    def recover_binding_pending_cleanup(
        self,
        binding: WebAnalysisLiveClaimBinding,
    ) -> WebAnalysisLiveClaimJournalEntry:
        """Move only one exact unfinished binding to cleanup-only recovery.

        This operation is for quiescent recovery after progression authority was
        lost.  It never recreates a handle, and an already-pending claim is
        returned without appending another event.
        """

        try:
            exact = _canonical_binding(binding)
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(connection, _load_claim(connection, exact.claim_id))
                if current.binding != exact:
                    raise WebAnalysisLiveClaimJournalError(
                        "Targeted recovery binding differs from durable state"
                    )
                if current.phase is WebAnalysisLiveClaimPhase.TERMINAL:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal live claim cannot enter targeted recovery"
                    )
                if current.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
                    return current
                return self._transition_to_pending_in_transaction(
                    connection,
                    current,
                    outcome=WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
                    occurred_at=self._now(),
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Targeted live claim recovery failed closed"
            ) from exc

    def recover_pending_cleanup(self) -> tuple[WebAnalysisLiveClaimJournalEntry, ...]:
        """Conservatively convert unfinished claims into cleanup-only records."""

        try:
            with self._write() as connection:
                self._validate_connection(connection)
                rows = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claims
                    WHERE phase IN ('reservation', 'live-start')
                    ORDER BY reserved_at, claim_id
                    """
                ).fetchall()
                for raw in rows:
                    current = _entry_from_row(connection, cast(sqlite3.Row, raw))
                    self._transition_to_pending_in_transaction(
                        connection,
                        current,
                        outcome=WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
                        occurred_at=self._now(),
                    )
                pending_rows = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claims
                    WHERE phase = 'pending-cleanup'
                    ORDER BY reserved_at, claim_id
                    """
                ).fetchall()
                return tuple(
                    _entry_from_row(connection, cast(sqlite3.Row, row)) for row in pending_rows
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError("Live claim recovery failed closed") from exc

    def record_cleanup_failure(
        self,
        entry: WebAnalysisLiveClaimJournalEntry,
        *,
        failure_digest: str,
    ) -> WebAnalysisLiveClaimJournalEntry:
        """Append a cleanup failure while keeping the claim pending and unusable."""

        _require_sha256(failure_digest, label="cleanup failure digest")
        try:
            expected = _canonical_entry(entry)
            if expected.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
                raise WebAnalysisLiveClaimJournalError(
                    "Cleanup failures require a pending-cleanup claim"
                )
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection, _load_claim(connection, expected.binding.claim_id)
                )
                if current != expected:
                    raise WebAnalysisLiveClaimJournalError(
                        "Cleanup failure claim differs from durable state"
                    )
                occurred_at = self._now()
                previous = current.event_digests[-1]
                ordinal = len(current.event_digests) + 1
                event_digest = _event_digest(
                    claim_id=current.binding.claim_id,
                    ordinal=ordinal,
                    event_type="cleanup-failed",
                    from_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                    to_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                    occurred_at=occurred_at,
                    pending_outcome=None,
                    terminal_disposition=None,
                    evidence_digest=failure_digest,
                    previous_event_digest=previous,
                )
                _insert_event(
                    connection,
                    claim_id=current.binding.claim_id,
                    ordinal=ordinal,
                    event_type="cleanup-failed",
                    from_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                    to_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                    occurred_at=occurred_at,
                    pending_outcome=None,
                    terminal_disposition=None,
                    evidence_digest=failure_digest,
                    previous_event_digest=previous,
                    event_digest=event_digest,
                )
                return _entry_from_row(
                    connection, _load_claim(connection, current.binding.claim_id)
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Cleanup failure recording failed closed"
            ) from exc

    def record_terminal_publication_intent(
        self,
        entry: WebAnalysisLiveClaimJournalEntry,
        *,
        output_root: Path,
        run_path: Path,
        run_id: str,
        receipt_digest: str,
        cleanup_result_digest: str,
        resource_absence_digest: str,
        disposition: WebAnalysisLiveClaimTerminalDisposition,
        live_attestation_digest: str | None,
    ) -> WebAnalysisLiveClaimTerminalPublication:
        """Commit the sole legal receipt publication before any Run appears."""

        if not isinstance(output_root, Path) or not isinstance(run_path, Path):
            raise WebAnalysisLiveClaimJournalError(
                "Terminal publication paths must be exact Path values"
            )
        if type(disposition) is not WebAnalysisLiveClaimTerminalDisposition:
            raise WebAnalysisLiveClaimJournalError("Terminal publication disposition is invalid")
        for digest, label in (
            (receipt_digest, "terminal publication receipt digest"),
            (cleanup_result_digest, "terminal publication cleanup digest"),
            (resource_absence_digest, "terminal publication absence digest"),
        ):
            _require_sha256(digest, label=label)
        if live_attestation_digest is not None:
            _require_sha256(
                live_attestation_digest,
                label="terminal publication live attestation digest",
            )
        try:
            expected = _canonical_entry(entry)
            if expected.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
                raise WebAnalysisLiveClaimJournalError(
                    "Terminal publication requires pending cleanup"
                )
            publication = WebAnalysisLiveClaimTerminalPublication(
                claimId=expected.binding.claim_id,
                claimDigest=expected.binding.claim_digest,
                pendingClaimStateDigest=expected.state_digest,
                outputRoot=os.path.abspath(output_root),
                runPath=os.path.abspath(run_path),
                runId=run_id,
                receiptDigest=receipt_digest,
                cleanupResultDigest=cleanup_result_digest,
                resourceAbsenceDigest=resource_absence_digest,
                intendedTerminalDisposition=disposition,
                liveAttestationDigest=live_attestation_digest,
            )
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection,
                    _load_claim(connection, expected.binding.claim_id),
                )
                if current != expected:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication claim differs from durable pending state"
                    )
                _gate_d_context_from_row(
                    _load_gate_d_context(connection, current.binding.claim_id),
                    binding=current.binding,
                )
                existing = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claim_terminal_publications
                    WHERE claim_id = ?
                    """,
                    (current.binding.claim_id,),
                ).fetchone()
                if existing is not None:
                    observed = _terminal_publication_from_row(cast(sqlite3.Row, existing))
                    if observed != publication:
                        raise WebAnalysisLiveClaimJournalError(
                            "Terminal publication intent was already equivocated"
                        )
                    return observed
                _insert_terminal_publication(connection, publication)
                observed = _terminal_publication_from_row(
                    _load_terminal_publication(connection, current.binding.claim_id)
                )
                if observed != publication:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication intent differs after recording"
                    )
                return observed
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Terminal publication intent failed closed; durable state requires inspection"
            ) from exc

    def anchor_terminal_publication(
        self,
        entry: WebAnalysisLiveClaimJournalEntry,
        publication: WebAnalysisLiveClaimTerminalPublication,
        candidate: VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
    ) -> WebAnalysisLiveClaimTerminalPublication:
        """CAS a root proven by the full unanchored-candidate receipt loader.

        A caller cannot supply a bare seal digest here: the call boundary
        requires the exact typed proof returned only after the candidate loader
        has checked the complete sealed receipt and its durable intent twice.
        """

        try:
            expected_entry = _canonical_entry(entry)
            expected_publication = _canonical_terminal_publication(publication)
            if type(candidate) is not VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate:
                raise WebAnalysisLiveClaimJournalError(
                    "Terminal publication anchor requires a verified candidate"
                )
            from pajin.web_assessment.analysis_skill_compact_live_receipts import (
                _take_verified_terminal_publication_candidate,
            )

            candidate_claim_id, candidate_intent_digest, candidate_root_digest = (
                _take_verified_terminal_publication_candidate(candidate, journal=self)
            )
            if expected_entry.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
                raise WebAnalysisLiveClaimJournalError(
                    "Terminal publication anchor requires pending cleanup"
                )
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection,
                    _load_claim(connection, expected_entry.binding.claim_id),
                )
                if current != expected_entry:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication anchor claim differs"
                    )
                stored = _terminal_publication_from_row(
                    _load_terminal_publication(connection, current.binding.claim_id)
                )
                if stored != expected_publication:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication anchor intent differs"
                    )
                if (
                    candidate_claim_id != stored.claim_id
                    or candidate_intent_digest != stored.intent_digest
                ):
                    raise WebAnalysisLiveClaimJournalError(
                        "Verified terminal publication candidate differs from intent"
                    )
                if stored.root_digest is not None:
                    if stored.root_digest != candidate_root_digest:
                        raise WebAnalysisLiveClaimJournalError(
                            "Terminal publication root was already equivocated"
                        )
                    return stored
                anchored = WebAnalysisLiveClaimTerminalPublication.model_validate(
                    {
                        **stored.model_dump(mode="python", by_alias=True),
                        "rootDigest": candidate_root_digest,
                        "publicationDigest": "",
                    }
                )
                cursor = connection.execute(
                    """
                    UPDATE web_analysis_live_claim_terminal_publications
                    SET root_digest = ?, publication_digest = ?
                    WHERE claim_id = ? AND intent_digest = ?
                      AND root_digest IS NULL AND publication_digest IS NULL
                    """,
                    (
                        anchored.root_digest,
                        anchored.publication_digest,
                        anchored.claim_id,
                        anchored.intent_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication root anchor lost its atomic race"
                    )
                observed = _terminal_publication_from_row(
                    _load_terminal_publication(connection, current.binding.claim_id)
                )
                if observed != anchored:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication root differs after anchoring"
                    )
                return observed
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Terminal publication root anchoring failed closed"
            ) from exc

    def finalize_terminal(
        self,
        entry: WebAnalysisLiveClaimJournalEntry,
        *,
        disposition: WebAnalysisLiveClaimTerminalDisposition,
        cleanup_result_digest: str,
        resource_absence_digest: str,
        terminal_receipt_digest: str,
    ) -> WebAnalysisLiveClaimJournalEntry:
        """Seal terminal only after positive cleanup-bound evidence is supplied."""

        if type(disposition) is not WebAnalysisLiveClaimTerminalDisposition:
            raise WebAnalysisLiveClaimJournalError("Terminal disposition is invalid")
        _require_sha256(cleanup_result_digest, label="cleanup result digest")
        _require_sha256(resource_absence_digest, label="resource absence digest")
        _require_sha256(terminal_receipt_digest, label="terminal receipt digest")
        try:
            expected = _canonical_entry(entry)
            if expected.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
                raise WebAnalysisLiveClaimJournalError(
                    "Terminal transition requires pending-cleanup"
                )
            if disposition is WebAnalysisLiveClaimTerminalDisposition.SUCCESS and (
                expected.dispatch_count != 1
                or expected.pending_outcome
                is not WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
            ):
                raise WebAnalysisLiveClaimJournalError(
                    "Terminal success requires one dispatch and observed success"
                )
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection, _load_claim(connection, expected.binding.claim_id)
                )
                if current != expected:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal claim differs from durable pending state"
                    )
                gate_d_row = connection.execute(
                    """
                    SELECT 1 FROM web_analysis_live_claim_gate_d_contexts
                    WHERE claim_id = ?
                    """,
                    (current.binding.claim_id,),
                ).fetchone()
                if gate_d_row is not None:
                    publication = _terminal_publication_from_row(
                        _load_terminal_publication(connection, current.binding.claim_id)
                    )
                    if (
                        publication.pending_claim_state_digest != current.state_digest
                        or publication.root_digest is None
                        or publication.publication_digest is None
                        or publication.intended_terminal_disposition is not disposition
                        or publication.cleanup_result_digest != cleanup_result_digest
                        or publication.resource_absence_digest != resource_absence_digest
                        or publication.receipt_digest != terminal_receipt_digest
                    ):
                        raise WebAnalysisLiveClaimJournalError(
                            "Terminal claim differs from its anchored publication"
                        )
                terminal_at = self._now()
                state_digest = _state_digest(
                    binding_digest=current.binding.claim_digest,
                    phase=WebAnalysisLiveClaimPhase.TERMINAL,
                    reserved_at=current.reserved_at,
                    live_started_at=current.live_started_at,
                    dispatch_started_at=current.dispatch_started_at,
                    pending_cleanup_at=current.pending_cleanup_at,
                    terminal_at=terminal_at,
                    pending_outcome=current.pending_outcome,
                    terminal_disposition=disposition,
                    cleanup_result_digest=cleanup_result_digest,
                    resource_absence_digest=resource_absence_digest,
                    terminal_receipt_digest=terminal_receipt_digest,
                    dispatch_count=current.dispatch_count,
                )
                cursor = connection.execute(
                    """
                    UPDATE web_analysis_live_claims
                    SET phase = ?, terminal_at = ?, terminal_disposition = ?,
                        cleanup_result_digest = ?, resource_absence_digest = ?,
                        terminal_receipt_digest = ?, state_digest = ?
                    WHERE claim_id = ? AND phase = ? AND state_digest = ?
                    """,
                    (
                        WebAnalysisLiveClaimPhase.TERMINAL.value,
                        terminal_at,
                        disposition.value,
                        cleanup_result_digest,
                        resource_absence_digest,
                        terminal_receipt_digest,
                        state_digest,
                        current.binding.claim_id,
                        WebAnalysisLiveClaimPhase.PENDING_CLEANUP.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal transition lost its atomic race"
                    )
                evidence_digest = _terminal_evidence_digest(
                    cleanup_result_digest=cleanup_result_digest,
                    resource_absence_digest=resource_absence_digest,
                    terminal_receipt_digest=terminal_receipt_digest,
                )
                previous = current.event_digests[-1]
                ordinal = len(current.event_digests) + 1
                event_digest = _event_digest(
                    claim_id=current.binding.claim_id,
                    ordinal=ordinal,
                    event_type="terminal",
                    from_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                    to_phase=WebAnalysisLiveClaimPhase.TERMINAL,
                    occurred_at=terminal_at,
                    pending_outcome=None,
                    terminal_disposition=disposition,
                    evidence_digest=evidence_digest,
                    previous_event_digest=previous,
                )
                _insert_event(
                    connection,
                    claim_id=current.binding.claim_id,
                    ordinal=ordinal,
                    event_type="terminal",
                    from_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
                    to_phase=WebAnalysisLiveClaimPhase.TERMINAL,
                    occurred_at=terminal_at,
                    pending_outcome=None,
                    terminal_disposition=disposition,
                    evidence_digest=evidence_digest,
                    previous_event_digest=previous,
                    event_digest=event_digest,
                )
                return _entry_from_row(
                    connection, _load_claim(connection, current.binding.claim_id)
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError("Terminal transition failed closed") from exc

    def inspect(self, claim_id: str) -> WebAnalysisLiveClaimJournalEntry | None:
        """Read audit state without recreating any consumed authority handle."""

        if type(claim_id) is not str or not claim_id.startswith("web-analysis-live-claim:"):
            raise WebAnalysisLiveClaimJournalError("Live claim ID is invalid")
        try:
            with self._readonly() as connection:
                self._validate_connection(connection)
                row = connection.execute(
                    "SELECT * FROM web_analysis_live_claims WHERE claim_id = ?", (claim_id,)
                ).fetchone()
                return None if row is None else _entry_from_row(connection, cast(sqlite3.Row, row))
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError("Live claim inspection failed closed") from exc

    def inspect_gate_d_context(
        self,
        claim_id: str,
    ) -> WebAnalysisLiveClaimGateDContext | None:
        """Read exact Gate-D evidence without recreating progression authority."""

        if type(claim_id) is not str or not claim_id.startswith("web-analysis-live-claim:"):
            raise WebAnalysisLiveClaimJournalError("Live claim ID is invalid")
        try:
            with self._readonly() as connection:
                self._validate_connection(connection)
                row = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claim_gate_d_contexts
                    WHERE claim_id = ?
                    """,
                    (claim_id,),
                ).fetchone()
                if row is None:
                    return None
                binding = _entry_from_row(connection, _load_claim(connection, claim_id)).binding
                return _gate_d_context_from_row(cast(sqlite3.Row, row), binding=binding)
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Gate-D context inspection failed closed"
            ) from exc

    def inspect_terminal_publication(
        self,
        claim_id: str,
    ) -> WebAnalysisLiveClaimTerminalPublication | None:
        """Read the durable same-publication intent or sealed-root anchor."""

        if type(claim_id) is not str or not claim_id.startswith("web-analysis-live-claim:"):
            raise WebAnalysisLiveClaimJournalError("Live claim ID is invalid")
        try:
            with self._readonly() as connection:
                self._validate_connection(connection)
                row = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claim_terminal_publications
                    WHERE claim_id = ?
                    """,
                    (claim_id,),
                ).fetchone()
                if row is None:
                    return None
                publication = _terminal_publication_from_row(cast(sqlite3.Row, row))
                claim = _entry_from_row(connection, _load_claim(connection, claim_id))
                if (
                    publication.claim_id != claim.binding.claim_id
                    or publication.claim_digest != claim.binding.claim_digest
                ):
                    raise WebAnalysisLiveClaimJournalError(
                        "Terminal publication differs from its live claim"
                    )
                return publication
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Terminal publication inspection failed closed"
            ) from exc

    def inspect_preparation(
        self, preparation_identity: str
    ) -> WebAnalysisLiveClaimJournalEntry | None:
        """Inspect one identity after an uncertain reservation result."""

        _require_sha256(preparation_identity, label="preparation identity")
        return self._inspect_identity("preparation_identity", preparation_identity)

    def inspect_authorization(
        self, authorization_identity: str
    ) -> WebAnalysisLiveClaimJournalEntry | None:
        """Inspect one identity after an uncertain reservation result."""

        _require_sha256(authorization_identity, label="authorization identity")
        return self._inspect_identity("authorization_identity", authorization_identity)

    def pending_cleanup_entries(self) -> tuple[WebAnalysisLiveClaimJournalEntry, ...]:
        """Return cleanup-only audit records without model-dispatch handles."""

        try:
            with self._readonly() as connection:
                self._validate_connection(connection)
                rows = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claims
                    WHERE phase = 'pending-cleanup'
                    ORDER BY reserved_at, claim_id
                    """
                ).fetchall()
                return tuple(_entry_from_row(connection, cast(sqlite3.Row, row)) for row in rows)
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Pending-cleanup inspection failed closed"
            ) from exc

    def _inspect_identity(
        self, column: Literal["preparation_identity", "authorization_identity"], value: str
    ) -> WebAnalysisLiveClaimJournalEntry | None:
        try:
            with self._readonly() as connection:
                self._validate_connection(connection)
                row = connection.execute(
                    f"SELECT * FROM web_analysis_live_claims WHERE {column} = ?", (value,)
                ).fetchone()
                return None if row is None else _entry_from_row(connection, cast(sqlite3.Row, row))
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Live claim identity inspection failed closed"
            ) from exc

    def _transition_to_live(
        self, expected: WebAnalysisLiveClaimJournalEntry
    ) -> WebAnalysisLiveClaimJournalEntry:
        try:
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection, _load_claim(connection, expected.binding.claim_id)
                )
                if current != expected:
                    raise WebAnalysisLiveClaimJournalError(
                        "Live-start claim differs from durable reservation"
                    )
                live_started_at = self._now()
                state_digest = _state_digest(
                    binding_digest=current.binding.claim_digest,
                    phase=WebAnalysisLiveClaimPhase.LIVE_START,
                    reserved_at=current.reserved_at,
                    live_started_at=live_started_at,
                    dispatch_started_at=None,
                    pending_cleanup_at=None,
                    terminal_at=None,
                    pending_outcome=None,
                    terminal_disposition=None,
                    cleanup_result_digest=None,
                    resource_absence_digest=None,
                    terminal_receipt_digest=None,
                    dispatch_count=0,
                )
                cursor = connection.execute(
                    """
                    UPDATE web_analysis_live_claims
                    SET phase = ?, live_started_at = ?, state_digest = ?
                    WHERE claim_id = ? AND phase = ? AND state_digest = ?
                    """,
                    (
                        WebAnalysisLiveClaimPhase.LIVE_START.value,
                        live_started_at,
                        state_digest,
                        current.binding.claim_id,
                        WebAnalysisLiveClaimPhase.RESERVATION.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise WebAnalysisLiveClaimJournalError(
                        "Live-start transition lost its atomic race"
                    )
                self._append_transition_event(
                    connection,
                    current=current,
                    event_type="live-start",
                    to_phase=WebAnalysisLiveClaimPhase.LIVE_START,
                    occurred_at=live_started_at,
                )
                return _entry_from_row(
                    connection, _load_claim(connection, current.binding.claim_id)
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError("Live-start transition failed closed") from exc

    def _mark_dispatch_started(
        self, expected: WebAnalysisLiveClaimJournalEntry
    ) -> WebAnalysisLiveClaimJournalEntry:
        try:
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection, _load_claim(connection, expected.binding.claim_id)
                )
                if current != expected or current.dispatch_count != 0:
                    raise WebAnalysisLiveClaimJournalError(
                        "Dispatch slot differs or was already consumed"
                    )
                context_row = connection.execute(
                    """
                    SELECT * FROM web_analysis_live_claim_gate_d_contexts
                    WHERE claim_id = ?
                    """,
                    (current.binding.claim_id,),
                ).fetchone()
                gate_d_context: WebAnalysisLiveClaimGateDContext | None = None
                if context_row is not None:
                    gate_d_context = _gate_d_context_from_row(
                        cast(sqlite3.Row, context_row),
                        binding=current.binding,
                    )
                    if gate_d_context.pre_dispatch_authorization_verification_digest is None:
                        raise WebAnalysisLiveClaimJournalError(
                            "Gate-D dispatch requires complete pre-dispatch context"
                        )
                    if gate_d_context.provider_route_attestation_digest is None:
                        raise WebAnalysisLiveClaimJournalError(
                            "Gate-D dispatch requires provider route attestation"
                        )
                dispatch_started_at = self._now()
                if (
                    gate_d_context is not None
                    and gate_d_context.pre_dispatch_authorization_evaluated_at is not None
                    and _parse_timestamp(dispatch_started_at)
                    < _parse_timestamp(gate_d_context.pre_dispatch_authorization_evaluated_at)
                ):
                    raise WebAnalysisLiveClaimJournalError(
                        "Dispatch marker predates Gate-D re-verification"
                    )
                if gate_d_context is not None:
                    expires_at = gate_d_context.pre_dispatch_authorization_expires_at
                    if expires_at is None or _parse_timestamp(
                        dispatch_started_at
                    ) >= _parse_timestamp(expires_at):
                        raise WebAnalysisLiveClaimJournalError(
                            "Gate-D authorization expired before dispatch marker"
                        )
                state_digest = _state_digest(
                    binding_digest=current.binding.claim_digest,
                    phase=WebAnalysisLiveClaimPhase.LIVE_START,
                    reserved_at=current.reserved_at,
                    live_started_at=current.live_started_at,
                    dispatch_started_at=dispatch_started_at,
                    pending_cleanup_at=None,
                    terminal_at=None,
                    pending_outcome=None,
                    terminal_disposition=None,
                    cleanup_result_digest=None,
                    resource_absence_digest=None,
                    terminal_receipt_digest=None,
                    dispatch_count=1,
                )
                cursor = connection.execute(
                    """
                    UPDATE web_analysis_live_claims
                    SET dispatch_started_at = ?, dispatch_count = 1, state_digest = ?
                    WHERE claim_id = ? AND phase = ? AND dispatch_count = 0
                      AND state_digest = ?
                    """,
                    (
                        dispatch_started_at,
                        state_digest,
                        current.binding.claim_id,
                        WebAnalysisLiveClaimPhase.LIVE_START.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise WebAnalysisLiveClaimJournalError("Dispatch slot lost its atomic race")
                self._append_transition_event(
                    connection,
                    current=current,
                    event_type="dispatch-started",
                    to_phase=WebAnalysisLiveClaimPhase.LIVE_START,
                    occurred_at=dispatch_started_at,
                )
                return _entry_from_row(
                    connection, _load_claim(connection, current.binding.claim_id)
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Dispatch-slot transition failed closed"
            ) from exc

    def _transition_to_pending(
        self,
        expected: WebAnalysisLiveClaimJournalEntry,
        *,
        outcome: WebAnalysisLiveClaimPendingOutcome,
    ) -> WebAnalysisLiveClaimJournalEntry:
        try:
            with self._write() as connection:
                self._validate_connection(connection)
                current = _entry_from_row(
                    connection, _load_claim(connection, expected.binding.claim_id)
                )
                if current != expected:
                    raise WebAnalysisLiveClaimJournalError(
                        "Pending-cleanup claim differs from durable state"
                    )
                return self._transition_to_pending_in_transaction(
                    connection, current, outcome=outcome, occurred_at=self._now()
                )
        except WebAnalysisLiveClaimJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
            SupervisorInvocationJournalError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Pending-cleanup transition failed closed"
            ) from exc

    def _transition_to_pending_in_transaction(
        self,
        connection: sqlite3.Connection,
        current: WebAnalysisLiveClaimJournalEntry,
        *,
        outcome: WebAnalysisLiveClaimPendingOutcome,
        occurred_at: str,
    ) -> WebAnalysisLiveClaimJournalEntry:
        if current.phase not in {
            WebAnalysisLiveClaimPhase.RESERVATION,
            WebAnalysisLiveClaimPhase.LIVE_START,
        }:
            raise WebAnalysisLiveClaimJournalError(
                "Only unfinished claims can enter pending-cleanup"
            )
        context_row = connection.execute(
            """
            SELECT * FROM web_analysis_live_claim_gate_d_contexts
            WHERE claim_id = ?
            """,
            (current.binding.claim_id,),
        ).fetchone()
        if context_row is not None:
            gate_d_context = _gate_d_context_from_row(
                cast(sqlite3.Row, context_row),
                binding=current.binding,
            )
            if (
                gate_d_context.pre_dispatch_authorization_evaluated_at is not None
                and _parse_timestamp(occurred_at)
                < _parse_timestamp(gate_d_context.pre_dispatch_authorization_evaluated_at)
            ):
                raise WebAnalysisLiveClaimJournalError(
                    "Pending-cleanup marker predates Gate-D re-verification"
                )
        state_digest = _state_digest(
            binding_digest=current.binding.claim_digest,
            phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
            reserved_at=current.reserved_at,
            live_started_at=current.live_started_at,
            dispatch_started_at=current.dispatch_started_at,
            pending_cleanup_at=occurred_at,
            terminal_at=None,
            pending_outcome=outcome,
            terminal_disposition=None,
            cleanup_result_digest=None,
            resource_absence_digest=None,
            terminal_receipt_digest=None,
            dispatch_count=current.dispatch_count,
        )
        cursor = connection.execute(
            """
            UPDATE web_analysis_live_claims
            SET phase = ?, pending_cleanup_at = ?, pending_outcome = ?, state_digest = ?
            WHERE claim_id = ? AND phase = ? AND state_digest = ?
            """,
            (
                WebAnalysisLiveClaimPhase.PENDING_CLEANUP.value,
                occurred_at,
                outcome.value,
                state_digest,
                current.binding.claim_id,
                current.phase.value,
                current.state_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise WebAnalysisLiveClaimJournalError(
                "Pending-cleanup transition lost its atomic race"
            )
        previous = current.event_digests[-1]
        ordinal = len(current.event_digests) + 1
        event_digest = _event_digest(
            claim_id=current.binding.claim_id,
            ordinal=ordinal,
            event_type="pending-cleanup",
            from_phase=current.phase,
            to_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
            occurred_at=occurred_at,
            pending_outcome=outcome,
            terminal_disposition=None,
            evidence_digest=None,
            previous_event_digest=previous,
        )
        _insert_event(
            connection,
            claim_id=current.binding.claim_id,
            ordinal=ordinal,
            event_type="pending-cleanup",
            from_phase=current.phase,
            to_phase=WebAnalysisLiveClaimPhase.PENDING_CLEANUP,
            occurred_at=occurred_at,
            pending_outcome=outcome,
            terminal_disposition=None,
            evidence_digest=None,
            previous_event_digest=previous,
            event_digest=event_digest,
        )
        return _entry_from_row(connection, _load_claim(connection, current.binding.claim_id))

    def _append_transition_event(
        self,
        connection: sqlite3.Connection,
        *,
        current: WebAnalysisLiveClaimJournalEntry,
        event_type: Literal["live-start", "dispatch-started"],
        to_phase: WebAnalysisLiveClaimPhase,
        occurred_at: str,
    ) -> None:
        previous = current.event_digests[-1]
        ordinal = len(current.event_digests) + 1
        event_digest = _event_digest(
            claim_id=current.binding.claim_id,
            ordinal=ordinal,
            event_type=event_type,
            from_phase=current.phase,
            to_phase=to_phase,
            occurred_at=occurred_at,
            pending_outcome=None,
            terminal_disposition=None,
            evidence_digest=None,
            previous_event_digest=previous,
        )
        _insert_event(
            connection,
            claim_id=current.binding.claim_id,
            ordinal=ordinal,
            event_type=event_type,
            from_phase=current.phase,
            to_phase=to_phase,
            occurred_at=occurred_at,
            pending_outcome=None,
            terminal_disposition=None,
            evidence_digest=None,
            previous_event_digest=previous,
            event_digest=event_digest,
        )

    def _require_handle(
        self,
        handle: _ClaimHandle,
        expected_type: type[_ClaimHandle],
        phase: WebAnalysisLiveClaimPhase,
    ) -> WebAnalysisLiveClaimJournalEntry:
        if type(handle) is not expected_type:
            raise WebAnalysisLiveClaimJournalError("Live claim handle type is invalid")
        entry = handle._require(self._authority)
        if entry.phase is not phase:
            raise WebAnalysisLiveClaimJournalError("Live claim handle phase is invalid")
        return entry

    def _now(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise WebAnalysisLiveClaimJournalError("Live claim clock must be timezone-aware")
        normalized = value.astimezone(UTC)
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        try:
            with host_work():
                opened_identity = _file_identity(self.path)
                with _write_transaction_opened(self.path) as connection:
                    yield connection
                if _file_identity(self.path) != opened_identity:
                    raise WebAnalysisLiveClaimJournalError(
                        "Live claim journal changed during a committed transaction"
                    )
                with _readonly_connection_opened(self.path) as committed:
                    self._validate_connection(committed)
                if _file_identity(self.path) != opened_identity:
                    raise WebAnalysisLiveClaimJournalError(
                        "Live claim journal changed after a committed transaction"
                    )
        except SupervisorInvocationJournalError as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Live claim journal path or transaction failed closed"
            ) from exc

    @contextmanager
    def _readonly(self) -> Iterator[sqlite3.Connection]:
        try:
            with host_work(), _readonly_connection_opened(self.path) as connection:
                yield connection
        except SupervisorInvocationJournalError as exc:
            raise WebAnalysisLiveClaimJournalError(
                "Live claim journal path or read failed closed"
            ) from exc

    def _validate_connection(self, connection: sqlite3.Connection) -> None:
        _validate_schema(connection)
        if _metadata(connection)["store_id"] != self._store_id:
            raise WebAnalysisLiveClaimJournalError(
                "Live claim journal changed from the opened store identity"
            )


def _initialize(path: Path, *, allow_create: bool) -> None:
    if type(allow_create) is not bool:
        raise WebAnalysisLiveClaimJournalError("Journal creation setting must be a boolean")
    _require_safe_path(path)
    _require_safe_sidecars(path)
    if not allow_create and (not path.exists() or path.stat().st_size == 0):
        raise WebAnalysisLiveClaimJournalError("Required live claim journal is missing")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.parent.chmod(0o700)
    _require_safe_path(path)
    existing_size = path.stat().st_size if path.exists() else 0
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode={'rwc' if allow_create else 'rw'}",
            uri=True,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN IMMEDIATE")
        tables = _application_tables(connection)
        if not tables:
            if existing_size != 0:
                raise WebAnalysisLiveClaimJournalError(
                    "Existing live claim journal has no trusted schema"
                )
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise WebAnalysisLiveClaimJournalError(
                    "Live claim journal requires DELETE journal mode"
                )
            for statement in _SCHEMA_OBJECT_SQL.values():
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO web_analysis_live_claim_metadata(key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(_SCHEMA_VERSION)),
                    ("schema_digest", _SCHEMA_DIGEST),
                    ("store_id", secrets.token_hex(32)),
                ),
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        _validate_schema(connection)
        connection.execute("COMMIT")
        if os.name == "posix":
            path.chmod(0o600)
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        if connection is not None:
            connection.close()
    _require_safe_path(path)
    _require_safe_sidecars(path)


def _validate_schema(connection: sqlite3.Connection) -> None:
    if _application_tables(connection) != _TABLES:
        raise WebAnalysisLiveClaimJournalError("Live claim journal table set differs")
    metadata = _metadata(connection)
    if metadata.keys() != {"schema_version", "schema_digest", "store_id"}:
        raise WebAnalysisLiveClaimJournalError("Live claim journal metadata keys differ")
    _require_sha256(metadata["store_id"], label="live claim store identity")
    user_version = connection.execute("PRAGMA user_version").fetchone()
    application_id = connection.execute("PRAGMA application_id").fetchone()
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        metadata["schema_version"] != str(_SCHEMA_VERSION)
        or metadata["schema_digest"] != _SCHEMA_DIGEST
        or user_version is None
        or user_version[0] != _SCHEMA_VERSION
        or application_id is None
        or application_id[0] != _APPLICATION_ID
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim journal connection or version differs")
    placeholders = ", ".join("?" for _ in _TABLES)
    rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(_TABLES), *sorted(_TABLES)),
    ).fetchall()
    actual = {
        (str(row["type"]), str(row["name"])): _normalize_schema_sql(str(row["sql"])) for row in rows
    }
    expected = {
        key: _normalize_schema_sql(statement) for key, statement in _SCHEMA_OBJECT_SQL.items()
    }
    if actual != expected:
        raise WebAnalysisLiveClaimJournalError("Live claim journal schema fingerprint differs")
    foreign_key_rows = connection.execute(
        "PRAGMA foreign_key_list(web_analysis_live_claim_events)"
    ).fetchall()
    signatures = {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
        )
        for row in foreign_key_rows
    }
    if signatures != {
        ("web_analysis_live_claims", "claim_id", "claim_id", "NO ACTION", "NO ACTION")
    }:
        raise WebAnalysisLiveClaimJournalError("Live claim journal foreign key differs")
    gate_d_foreign_key_rows = connection.execute(
        "PRAGMA foreign_key_list(web_analysis_live_claim_gate_d_contexts)"
    ).fetchall()
    gate_d_signatures = {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
        )
        for row in gate_d_foreign_key_rows
    }
    if gate_d_signatures != {
        ("web_analysis_live_claims", "claim_id", "claim_id", "NO ACTION", "NO ACTION")
    }:
        raise WebAnalysisLiveClaimJournalError("Live claim Gate-D foreign key differs")
    publication_foreign_key_rows = connection.execute(
        "PRAGMA foreign_key_list(web_analysis_live_claim_terminal_publications)"
    ).fetchall()
    publication_signatures = {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
        )
        for row in publication_foreign_key_rows
    }
    if publication_signatures != {
        ("web_analysis_live_claims", "claim_id", "claim_id", "NO ACTION", "NO ACTION")
    }:
        raise WebAnalysisLiveClaimJournalError(
            "Live claim terminal publication foreign key differs"
        )
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise WebAnalysisLiveClaimJournalError("Live claim journal has orphaned events")
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise WebAnalysisLiveClaimJournalError("Live claim journal integrity check failed")


def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
    rows = connection.execute(
        "SELECT key, value FROM web_analysis_live_claim_metadata ORDER BY key"
    ).fetchall()
    return {str(row["key"]): str(row["value"]) for row in rows}


def _binding_bytes(binding: WebAnalysisLiveClaimBinding) -> bytes:
    return canonical_json_bytes(
        binding.model_dump(mode="json", by_alias=True),
        label="Web analysis live claim binding",
        max_bytes=_MAX_BINDING_BYTES,
    )


def _timestamp_from_datetime(value: datetime, *, label: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WebAnalysisLiveClaimJournalError(f"{label} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise WebAnalysisLiveClaimJournalError(f"{label} must use UTC")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    _validate_timestamp(value, field="timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_lease_ids(value: tuple[str, ...]) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) != 1:
        raise WebAnalysisLiveClaimJournalError(
            "Gate-D context requires a tuple containing exactly one lease identity"
        )
    for lease_id in value:
        if type(lease_id) is not str or len(lease_id) != 38 or not lease_id.startswith("lease_"):
            raise WebAnalysisLiveClaimJournalError("Gate-D lease identity is invalid")
        suffix = lease_id.removeprefix("lease_")
        try:
            decoded = bytes.fromhex(suffix)
        except ValueError as exc:
            raise WebAnalysisLiveClaimJournalError("Gate-D lease identity is invalid") from exc
        if len(decoded) != 16 or suffix != suffix.lower():
            raise WebAnalysisLiveClaimJournalError("Gate-D lease identity is invalid")
    return value


def _lease_ids_bytes(lease_ids: tuple[str, ...]) -> bytes:
    return canonical_json_bytes(
        lease_ids,
        label="Web analysis Gate-D lease identities",
        max_bytes=512,
    )


def _insert_gate_d_context(
    connection: sqlite3.Connection,
    context: WebAnalysisLiveClaimGateDContext,
) -> None:
    connection.execute(
        """
        INSERT INTO web_analysis_live_claim_gate_d_contexts (
            claim_id, claim_digest,
            initial_authorization_verification_digest,
            initial_authorization_evaluated_at, initial_authorization_expires_at,
            pre_dispatch_authorization_verification_digest,
            pre_dispatch_authorization_evaluated_at,
            pre_dispatch_authorization_expires_at,
            provider_route_attestation_digest,
            transport_execution_id, lease_ids_json,
            worker_context_digest, job_metadata_digest,
            transport_binding_digest, context_digest
        ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?)
        """,
        (
            context.claim_id,
            context.claim_digest,
            context.initial_authorization_verification_digest,
            context.initial_authorization_evaluated_at,
            context.initial_authorization_expires_at,
            context.context_digest,
        ),
    )


def _load_gate_d_context(connection: sqlite3.Connection, claim_id: str) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT * FROM web_analysis_live_claim_gate_d_contexts
        WHERE claim_id = ?
        """,
        (claim_id,),
    ).fetchone()
    if row is None:
        raise WebAnalysisLiveClaimJournalError("Gate-D context was not found")
    return cast(sqlite3.Row, row)


def _gate_d_context_from_row(
    row: sqlite3.Row,
    *,
    binding: WebAnalysisLiveClaimBinding,
) -> WebAnalysisLiveClaimGateDContext:
    try:
        lease_ids_raw = row["lease_ids_json"]
        lease_ids: tuple[str, ...] | None
        if lease_ids_raw is None:
            lease_ids = None
        else:
            if type(lease_ids_raw) is not bytes or not lease_ids_raw:
                raise WebAnalysisLiveClaimJournalError("Gate-D lease identity bytes are invalid")
            decoded = parse_strict_json_bytes(
                lease_ids_raw,
                label="Web analysis Gate-D lease identities",
                max_bytes=512,
            )
            if type(decoded) is not list:
                raise WebAnalysisLiveClaimJournalError("Gate-D lease identity list is invalid")
            lease_ids = _canonical_lease_ids(tuple(decoded))
            if _lease_ids_bytes(lease_ids) != lease_ids_raw:
                raise WebAnalysisLiveClaimJournalError(
                    "Gate-D lease identity bytes are not canonical"
                )
        context = WebAnalysisLiveClaimGateDContext(
            claimId=_required_text(row, "claim_id"),
            claimDigest=_required_digest(row, "claim_digest"),
            initialAuthorizationVerificationDigest=_required_digest(
                row,
                "initial_authorization_verification_digest",
            ),
            initialAuthorizationEvaluatedAt=_required_timestamp(
                row,
                "initial_authorization_evaluated_at",
            ),
            initialAuthorizationExpiresAt=_required_timestamp(
                row,
                "initial_authorization_expires_at",
            ),
            preDispatchAuthorizationVerificationDigest=_optional_digest(
                row,
                "pre_dispatch_authorization_verification_digest",
            ),
            preDispatchAuthorizationEvaluatedAt=_optional_timestamp(
                row,
                "pre_dispatch_authorization_evaluated_at",
            ),
            preDispatchAuthorizationExpiresAt=_optional_timestamp(
                row,
                "pre_dispatch_authorization_expires_at",
            ),
            providerRouteAttestationDigest=_optional_digest(
                row,
                "provider_route_attestation_digest",
            ),
            transportExecutionId=_optional_text(row, "transport_execution_id"),
            leaseIds=lease_ids,
            workerContextDigest=_optional_digest(row, "worker_context_digest"),
            jobMetadataDigest=_optional_digest(row, "job_metadata_digest"),
            transportBindingDigest=_optional_digest(row, "transport_binding_digest"),
            contextDigest=_required_digest(row, "context_digest"),
        )
        if context.claim_id != binding.claim_id or context.claim_digest != binding.claim_digest:
            raise WebAnalysisLiveClaimJournalError("Gate-D context differs from its live claim")
        if (
            context.transport_execution_id is not None
            and context.transport_execution_id != f"exec_{binding.resources.resource_owner}"
        ):
            raise WebAnalysisLiveClaimJournalError(
                "Gate-D transport execution differs from its live claim"
            )
        return context
    except WebAnalysisLiveClaimJournalError:
        raise
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError(
            "Gate-D context row failed integrity checks"
        ) from exc


def _canonical_terminal_publication(
    publication: WebAnalysisLiveClaimTerminalPublication,
) -> WebAnalysisLiveClaimTerminalPublication:
    if type(publication) is not WebAnalysisLiveClaimTerminalPublication:
        raise WebAnalysisLiveClaimJournalError("Terminal publication type is invalid")
    try:
        return WebAnalysisLiveClaimTerminalPublication.model_validate(
            publication.model_dump(mode="python", by_alias=True)
        )
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError("Terminal publication is invalid") from exc


def _insert_terminal_publication(
    connection: sqlite3.Connection,
    publication: WebAnalysisLiveClaimTerminalPublication,
) -> None:
    connection.execute(
        """
        INSERT INTO web_analysis_live_claim_terminal_publications (
            claim_id, claim_digest, pending_claim_state_digest,
            output_root, run_path, run_id, receipt_digest,
            cleanup_result_digest, resource_absence_digest,
            intended_terminal_disposition, live_attestation_digest,
            intent_digest, root_digest, publication_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            publication.claim_id,
            publication.claim_digest,
            publication.pending_claim_state_digest,
            publication.output_root,
            publication.run_path,
            publication.run_id,
            publication.receipt_digest,
            publication.cleanup_result_digest,
            publication.resource_absence_digest,
            publication.intended_terminal_disposition.value,
            publication.live_attestation_digest,
            publication.intent_digest,
            publication.root_digest,
            publication.publication_digest,
        ),
    )


def _load_terminal_publication(
    connection: sqlite3.Connection,
    claim_id: str,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT * FROM web_analysis_live_claim_terminal_publications
        WHERE claim_id = ?
        """,
        (claim_id,),
    ).fetchone()
    if row is None:
        raise WebAnalysisLiveClaimJournalError("Terminal publication was not found")
    return cast(sqlite3.Row, row)


def _terminal_publication_from_row(
    row: sqlite3.Row,
) -> WebAnalysisLiveClaimTerminalPublication:
    try:
        return WebAnalysisLiveClaimTerminalPublication(
            claimId=_required_text(row, "claim_id"),
            claimDigest=_required_digest(row, "claim_digest"),
            pendingClaimStateDigest=_required_digest(row, "pending_claim_state_digest"),
            outputRoot=_required_text(row, "output_root"),
            runPath=_required_text(row, "run_path"),
            runId=_required_text(row, "run_id"),
            receiptDigest=_required_digest(row, "receipt_digest"),
            cleanupResultDigest=_required_digest(row, "cleanup_result_digest"),
            resourceAbsenceDigest=_required_digest(row, "resource_absence_digest"),
            intendedTerminalDisposition=WebAnalysisLiveClaimTerminalDisposition(
                _required_text(row, "intended_terminal_disposition")
            ),
            liveAttestationDigest=_optional_digest(row, "live_attestation_digest"),
            intentDigest=_required_digest(row, "intent_digest"),
            rootDigest=_optional_digest(row, "root_digest"),
            publicationDigest=_optional_digest(row, "publication_digest"),
        )
    except WebAnalysisLiveClaimJournalError:
        raise
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError(
            "Terminal publication row failed integrity checks"
        ) from exc


def _canonical_binding(binding: WebAnalysisLiveClaimBinding) -> WebAnalysisLiveClaimBinding:
    if type(binding) is not WebAnalysisLiveClaimBinding:
        raise WebAnalysisLiveClaimJournalError("Live claim binding type is invalid")
    try:
        return WebAnalysisLiveClaimBinding.model_validate(
            binding.model_dump(mode="python", by_alias=True)
        )
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError("Live claim binding is invalid") from exc


def _canonical_entry(entry: WebAnalysisLiveClaimJournalEntry) -> WebAnalysisLiveClaimJournalEntry:
    if type(entry) is not WebAnalysisLiveClaimJournalEntry:
        raise WebAnalysisLiveClaimJournalError("Live claim entry type is invalid")
    try:
        return WebAnalysisLiveClaimJournalEntry.model_validate(
            entry.model_dump(mode="python", by_alias=True)
        )
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError("Live claim entry is invalid") from exc


def _entry_from_row(
    connection: sqlite3.Connection, row: sqlite3.Row
) -> WebAnalysisLiveClaimJournalEntry:
    try:
        binding_bytes = _required_bytes(row, "canonical_binding")
        decoded = parse_strict_json_bytes(
            binding_bytes,
            label="Web analysis live claim binding",
            max_bytes=_MAX_BINDING_BYTES,
        )
        binding = WebAnalysisLiveClaimBinding.model_validate(decoded)
        if _binding_bytes(binding) != binding_bytes:
            raise WebAnalysisLiveClaimJournalError("Live claim canonical binding bytes differ")
        if (
            _required_text(row, "claim_id") != binding.claim_id
            or _required_digest(row, "claim_digest") != binding.claim_digest
            or _required_digest(row, "admission_digest") != binding.admission_digest
            or _required_digest(row, "preparation_identity") != binding.preparation_identity
            or _required_digest(row, "authorization_identity") != binding.authorization_identity
            or _required_digest(row, "authorization_envelope_digest")
            != binding.authorization_envelope_digest
            or _required_text(row, "resource_owner") != binding.resources.resource_owner
        ):
            raise WebAnalysisLiveClaimJournalError("Live claim row anchors differ")
        phase = WebAnalysisLiveClaimPhase(_required_text(row, "phase"))
        pending_raw = _optional_text(row, "pending_outcome")
        disposition_raw = _optional_text(row, "terminal_disposition")
        pending = (
            WebAnalysisLiveClaimPendingOutcome(pending_raw) if pending_raw is not None else None
        )
        disposition = (
            WebAnalysisLiveClaimTerminalDisposition(disposition_raw)
            if disposition_raw is not None
            else None
        )
        events = _verified_event_digests(
            connection,
            binding=binding,
            phase=phase,
            reserved_at=_required_timestamp(row, "reserved_at"),
            live_started_at=_optional_timestamp(row, "live_started_at"),
            dispatch_started_at=_optional_timestamp(row, "dispatch_started_at"),
            pending_cleanup_at=_optional_timestamp(row, "pending_cleanup_at"),
            terminal_at=_optional_timestamp(row, "terminal_at"),
            pending_outcome=pending,
            terminal_disposition=disposition,
            cleanup_result_digest=_optional_digest(row, "cleanup_result_digest"),
            resource_absence_digest=_optional_digest(row, "resource_absence_digest"),
            terminal_receipt_digest=_optional_digest(row, "terminal_receipt_digest"),
            dispatch_count=_required_dispatch_count(row),
        )
        return WebAnalysisLiveClaimJournalEntry(
            binding=binding,
            phase=phase,
            reservedAt=_required_timestamp(row, "reserved_at"),
            liveStartedAt=_optional_timestamp(row, "live_started_at"),
            dispatchStartedAt=_optional_timestamp(row, "dispatch_started_at"),
            pendingCleanupAt=_optional_timestamp(row, "pending_cleanup_at"),
            terminalAt=_optional_timestamp(row, "terminal_at"),
            pendingOutcome=pending,
            terminalDisposition=disposition,
            cleanupResultDigest=_optional_digest(row, "cleanup_result_digest"),
            resourceAbsenceDigest=_optional_digest(row, "resource_absence_digest"),
            terminalReceiptDigest=_optional_digest(row, "terminal_receipt_digest"),
            dispatchCount=_required_dispatch_count(row),
            stateDigest=_required_digest(row, "state_digest"),
            eventDigests=events,
        )
    except WebAnalysisLiveClaimJournalError:
        raise
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebAnalysisLiveClaimJournalError("Live claim row failed integrity checks") from exc


@dataclass(slots=True)
class _EventReplay:
    current_phase: WebAnalysisLiveClaimPhase | None = None
    live_at: str | None = None
    dispatch_at: str | None = None
    pending_at: str | None = None
    terminal_at: str | None = None
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None = None
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None = None
    dispatch_count: int = 0


@dataclass(frozen=True, slots=True)
class _ParsedEvent:
    ordinal: int
    event_type: str
    from_phase: WebAnalysisLiveClaimPhase | None
    to_phase: WebAnalysisLiveClaimPhase
    occurred_at: str
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None
    evidence_digest: str | None


def _verified_event_digests(
    connection: sqlite3.Connection,
    *,
    binding: WebAnalysisLiveClaimBinding,
    phase: WebAnalysisLiveClaimPhase,
    reserved_at: str,
    live_started_at: str | None,
    dispatch_started_at: str | None,
    pending_cleanup_at: str | None,
    terminal_at: str | None,
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None,
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None,
    cleanup_result_digest: str | None,
    resource_absence_digest: str | None,
    terminal_receipt_digest: str | None,
    dispatch_count: Literal[0, 1],
) -> tuple[str, ...]:
    rows = connection.execute(
        """
        SELECT * FROM web_analysis_live_claim_events
        WHERE claim_id = ? ORDER BY ordinal
        """,
        (binding.claim_id,),
    ).fetchall()
    if not rows:
        raise WebAnalysisLiveClaimJournalError("Live claim event history is absent")
    previous: str | None = None
    digests: list[str] = []
    replay = _EventReplay()
    for expected_ordinal, raw in enumerate(rows, start=1):
        row = cast(sqlite3.Row, raw)
        ordinal = _required_integer(row, "ordinal")
        if ordinal != expected_ordinal:
            raise WebAnalysisLiveClaimJournalError("Live claim event ordinal differs")
        event_type = _required_text(row, "event_type")
        from_raw = _optional_text(row, "from_phase")
        to_phase = WebAnalysisLiveClaimPhase(_required_text(row, "to_phase"))
        from_phase = WebAnalysisLiveClaimPhase(from_raw) if from_raw is not None else None
        occurred_at = _required_timestamp(row, "occurred_at")
        pending_raw = _optional_text(row, "pending_outcome")
        event_pending = (
            WebAnalysisLiveClaimPendingOutcome(pending_raw) if pending_raw is not None else None
        )
        disposition_raw = _optional_text(row, "terminal_disposition")
        event_disposition = (
            WebAnalysisLiveClaimTerminalDisposition(disposition_raw)
            if disposition_raw is not None
            else None
        )
        evidence_digest = _optional_digest(row, "evidence_digest")
        previous_digest = _optional_digest(row, "previous_event_digest")
        if previous_digest != previous or from_phase is not replay.current_phase:
            raise WebAnalysisLiveClaimJournalError("Live claim event chain differs")
        event = _ParsedEvent(
            ordinal=ordinal,
            event_type=event_type,
            from_phase=from_phase,
            to_phase=to_phase,
            occurred_at=occurred_at,
            pending_outcome=event_pending,
            terminal_disposition=event_disposition,
            evidence_digest=evidence_digest,
        )
        _apply_event(
            replay,
            event,
            reserved_at=reserved_at,
            cleanup_result_digest=cleanup_result_digest,
            resource_absence_digest=resource_absence_digest,
            terminal_receipt_digest=terminal_receipt_digest,
        )
        digest = _required_digest(row, "event_digest")
        expected_digest = _event_digest(
            claim_id=binding.claim_id,
            ordinal=ordinal,
            event_type=event_type,
            from_phase=from_phase,
            to_phase=to_phase,
            occurred_at=occurred_at,
            pending_outcome=event_pending,
            terminal_disposition=event_disposition,
            evidence_digest=evidence_digest,
            previous_event_digest=previous,
        )
        if digest != expected_digest:
            raise WebAnalysisLiveClaimJournalError("Live claim event digest differs")
        previous = digest
        replay.current_phase = to_phase
        digests.append(digest)
    if (
        replay.current_phase is not phase
        or replay.live_at != live_started_at
        or replay.dispatch_at != dispatch_started_at
        or replay.pending_at != pending_cleanup_at
        or replay.terminal_at != terminal_at
        or replay.pending_outcome is not pending_outcome
        or replay.terminal_disposition is not terminal_disposition
        or replay.dispatch_count != dispatch_count
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim event replay differs from state")
    return tuple(digests)


def _apply_event(
    replay: _EventReplay,
    event: _ParsedEvent,
    *,
    reserved_at: str,
    cleanup_result_digest: str | None,
    resource_absence_digest: str | None,
    terminal_receipt_digest: str | None,
) -> None:
    if event.event_type == "reservation":
        _apply_reservation_event(event, reserved_at=reserved_at)
    elif event.event_type == "live-start":
        _apply_live_start_event(replay, event)
    elif event.event_type == "dispatch-started":
        _apply_dispatch_event(replay, event)
    elif event.event_type == "pending-cleanup":
        _apply_pending_event(replay, event)
    elif event.event_type == "cleanup-failed":
        _apply_cleanup_failure_event(event)
    elif event.event_type == "terminal":
        _apply_terminal_event(
            replay,
            event,
            cleanup_result_digest=cleanup_result_digest,
            resource_absence_digest=resource_absence_digest,
            terminal_receipt_digest=terminal_receipt_digest,
        )
    else:
        raise WebAnalysisLiveClaimJournalError("Live claim event type is invalid")
    if event.event_type != "pending-cleanup" and event.pending_outcome is not None:
        raise WebAnalysisLiveClaimJournalError("Live claim event pending outcome differs")
    if event.event_type != "terminal" and event.terminal_disposition is not None:
        raise WebAnalysisLiveClaimJournalError("Live claim event terminal disposition differs")
    if event.event_type not in {"cleanup-failed", "terminal"} and (
        event.evidence_digest is not None
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim event evidence differs")


def _apply_reservation_event(event: _ParsedEvent, *, reserved_at: str) -> None:
    if (
        event.ordinal != 1
        or event.from_phase is not None
        or event.to_phase is not WebAnalysisLiveClaimPhase.RESERVATION
        or event.occurred_at != reserved_at
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim reservation event differs")


def _apply_live_start_event(replay: _EventReplay, event: _ParsedEvent) -> None:
    if (
        event.from_phase is not WebAnalysisLiveClaimPhase.RESERVATION
        or event.to_phase is not WebAnalysisLiveClaimPhase.LIVE_START
        or replay.live_at is not None
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim live-start event differs")
    replay.live_at = event.occurred_at


def _apply_dispatch_event(replay: _EventReplay, event: _ParsedEvent) -> None:
    if (
        event.from_phase is not WebAnalysisLiveClaimPhase.LIVE_START
        or event.to_phase is not WebAnalysisLiveClaimPhase.LIVE_START
        or replay.dispatch_count != 0
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim dispatch event differs")
    replay.dispatch_at = event.occurred_at
    replay.dispatch_count = 1


def _apply_pending_event(replay: _EventReplay, event: _ParsedEvent) -> None:
    if (
        event.from_phase
        not in {
            WebAnalysisLiveClaimPhase.RESERVATION,
            WebAnalysisLiveClaimPhase.LIVE_START,
        }
        or event.to_phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
        or event.pending_outcome is None
        or replay.pending_at is not None
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim pending-cleanup event differs")
    replay.pending_at = event.occurred_at
    replay.pending_outcome = event.pending_outcome


def _apply_cleanup_failure_event(event: _ParsedEvent) -> None:
    if (
        event.from_phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
        or event.to_phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
        or event.evidence_digest is None
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim cleanup event differs")


def _apply_terminal_event(
    replay: _EventReplay,
    event: _ParsedEvent,
    *,
    cleanup_result_digest: str | None,
    resource_absence_digest: str | None,
    terminal_receipt_digest: str | None,
) -> None:
    if (
        event.from_phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
        or event.to_phase is not WebAnalysisLiveClaimPhase.TERMINAL
        or event.terminal_disposition is None
        or replay.terminal_at is not None
        or cleanup_result_digest is None
        or resource_absence_digest is None
        or terminal_receipt_digest is None
        or event.evidence_digest
        != _terminal_evidence_digest(
            cleanup_result_digest=cleanup_result_digest,
            resource_absence_digest=resource_absence_digest,
            terminal_receipt_digest=terminal_receipt_digest,
        )
    ):
        raise WebAnalysisLiveClaimJournalError("Live claim terminal event differs")
    replay.terminal_at = event.occurred_at
    replay.terminal_disposition = event.terminal_disposition


def _require_phase_shape(entry: WebAnalysisLiveClaimJournalEntry) -> None:
    if entry.phase is WebAnalysisLiveClaimPhase.RESERVATION:
        valid = (
            entry.live_started_at is None
            and entry.dispatch_started_at is None
            and entry.pending_cleanup_at is None
            and entry.terminal_at is None
            and entry.pending_outcome is None
            and entry.terminal_disposition is None
            and entry.cleanup_result_digest is None
            and entry.resource_absence_digest is None
            and entry.terminal_receipt_digest is None
            and entry.dispatch_count == 0
        )
    elif entry.phase is WebAnalysisLiveClaimPhase.LIVE_START:
        valid = (
            entry.live_started_at is not None
            and entry.pending_cleanup_at is None
            and entry.terminal_at is None
            and entry.pending_outcome is None
            and entry.terminal_disposition is None
            and entry.cleanup_result_digest is None
            and entry.resource_absence_digest is None
            and entry.terminal_receipt_digest is None
            and ((entry.dispatch_count == 0) == (entry.dispatch_started_at is None))
        )
    elif entry.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
        valid = (
            entry.pending_cleanup_at is not None
            and entry.terminal_at is None
            and entry.pending_outcome is not None
            and entry.terminal_disposition is None
            and entry.cleanup_result_digest is None
            and entry.resource_absence_digest is None
            and entry.terminal_receipt_digest is None
            and ((entry.dispatch_count == 0) == (entry.dispatch_started_at is None))
        )
    else:
        valid = (
            entry.pending_cleanup_at is not None
            and entry.terminal_at is not None
            and entry.pending_outcome is not None
            and entry.terminal_disposition is not None
            and entry.cleanup_result_digest is not None
            and entry.resource_absence_digest is not None
            and entry.terminal_receipt_digest is not None
            and ((entry.dispatch_count == 0) == (entry.dispatch_started_at is None))
            and (
                entry.terminal_disposition is not WebAnalysisLiveClaimTerminalDisposition.SUCCESS
                or (
                    entry.dispatch_count == 1
                    and entry.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
                )
            )
        )
    if not valid:
        raise ValueError("Live claim phase fields differ")


def _state_digest(
    *,
    binding_digest: str,
    phase: WebAnalysisLiveClaimPhase,
    reserved_at: str,
    live_started_at: str | None,
    dispatch_started_at: str | None,
    pending_cleanup_at: str | None,
    terminal_at: str | None,
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None,
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None,
    cleanup_result_digest: str | None,
    resource_absence_digest: str | None,
    terminal_receipt_digest: str | None,
    dispatch_count: int,
) -> str:
    return _digest(
        "pajin.web-analysis.live-claim-state/v1",
        {
            "bindingDigest": binding_digest,
            "phase": phase.value,
            "reservedAt": reserved_at,
            "liveStartedAt": live_started_at,
            "dispatchStartedAt": dispatch_started_at,
            "pendingCleanupAt": pending_cleanup_at,
            "terminalAt": terminal_at,
            "pendingOutcome": pending_outcome.value if pending_outcome is not None else None,
            "terminalDisposition": (
                terminal_disposition.value if terminal_disposition is not None else None
            ),
            "cleanupResultDigest": cleanup_result_digest,
            "resourceAbsenceDigest": resource_absence_digest,
            "terminalReceiptDigest": terminal_receipt_digest,
            "dispatchCount": dispatch_count,
        },
    )


def _event_digest(
    *,
    claim_id: str,
    ordinal: int,
    event_type: str,
    from_phase: WebAnalysisLiveClaimPhase | None,
    to_phase: WebAnalysisLiveClaimPhase,
    occurred_at: str,
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None,
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None,
    evidence_digest: str | None,
    previous_event_digest: str | None,
) -> str:
    return _digest(
        "pajin.web-analysis.live-claim-event/v1",
        {
            "claimId": claim_id,
            "ordinal": ordinal,
            "eventType": event_type,
            "fromPhase": from_phase.value if from_phase is not None else None,
            "toPhase": to_phase.value,
            "occurredAt": occurred_at,
            "pendingOutcome": (pending_outcome.value if pending_outcome is not None else None),
            "terminalDisposition": (
                terminal_disposition.value if terminal_disposition is not None else None
            ),
            "evidenceDigest": evidence_digest,
            "previousEventDigest": previous_event_digest,
        },
    )


def _terminal_evidence_digest(
    *,
    cleanup_result_digest: str,
    resource_absence_digest: str,
    terminal_receipt_digest: str,
) -> str:
    return _digest(
        "pajin.web-analysis.live-claim-terminal-evidence/v1",
        {
            "cleanupResultDigest": cleanup_result_digest,
            "resourceAbsenceDigest": resource_absence_digest,
            "terminalReceiptDigest": terminal_receipt_digest,
        },
    )


def _insert_event(
    connection: sqlite3.Connection,
    *,
    claim_id: str,
    ordinal: int,
    event_type: str,
    from_phase: WebAnalysisLiveClaimPhase | None,
    to_phase: WebAnalysisLiveClaimPhase,
    occurred_at: str,
    pending_outcome: WebAnalysisLiveClaimPendingOutcome | None,
    terminal_disposition: WebAnalysisLiveClaimTerminalDisposition | None,
    evidence_digest: str | None,
    previous_event_digest: str | None,
    event_digest: str,
) -> None:
    connection.execute(
        """
        INSERT INTO web_analysis_live_claim_events (
            claim_id, ordinal, event_type, from_phase, to_phase, occurred_at,
            pending_outcome, terminal_disposition, evidence_digest,
            previous_event_digest, event_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            claim_id,
            ordinal,
            event_type,
            from_phase.value if from_phase is not None else None,
            to_phase.value,
            occurred_at,
            pending_outcome.value if pending_outcome is not None else None,
            terminal_disposition.value if terminal_disposition is not None else None,
            evidence_digest,
            previous_event_digest,
            event_digest,
        ),
    )


def _load_claim(connection: sqlite3.Connection, claim_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM web_analysis_live_claims WHERE claim_id = ?", (claim_id,)
    ).fetchone()
    if row is None:
        raise WebAnalysisLiveClaimJournalError("Live claim was not found")
    return cast(sqlite3.Row, row)


def _require_sha256(value: str, *, label: str) -> None:
    if type(value) is not str or len(value) != 64:
        raise WebAnalysisLiveClaimJournalError(f"{label} is invalid")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise WebAnalysisLiveClaimJournalError(f"{label} is invalid") from exc
    if len(decoded) != 32 or value != value.lower():
        raise WebAnalysisLiveClaimJournalError(f"{label} is invalid")


def _required_text(row: sqlite3.Row, field: str) -> str:
    value = row[field]
    if type(value) is not str or not value:
        raise WebAnalysisLiveClaimJournalError(f"Live claim {field} is invalid")
    return value


def _optional_text(row: sqlite3.Row, field: str) -> str | None:
    value = row[field]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise WebAnalysisLiveClaimJournalError(f"Live claim {field} is invalid")
    return value


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if type(value) is not bytes or not value:
        raise WebAnalysisLiveClaimJournalError(f"Live claim {field} is invalid")
    return value


def _required_digest(row: sqlite3.Row, field: str) -> str:
    value = _required_text(row, field)
    _require_sha256(value, label=field)
    return value


def _optional_digest(row: sqlite3.Row, field: str) -> str | None:
    value = _optional_text(row, field)
    if value is not None:
        _require_sha256(value, label=field)
    return value


def _required_timestamp(row: sqlite3.Row, field: str) -> str:
    value = _required_text(row, field)
    _validate_timestamp(value, field=field)
    return value


def _optional_timestamp(row: sqlite3.Row, field: str) -> str | None:
    value = _optional_text(row, field)
    if value is not None:
        _validate_timestamp(value, field=field)
    return value


def _validate_timestamp(value: str, *, field: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WebAnalysisLiveClaimJournalError(f"Live claim {field} is invalid") from exc
    if (
        not value.endswith("Z")
        or len(value) != 27
        or parsed.tzinfo is None
        or parsed.utcoffset() != UTC.utcoffset(parsed)
    ):
        raise WebAnalysisLiveClaimJournalError(f"Live claim {field} is invalid")


def _required_integer(row: sqlite3.Row, field: str) -> int:
    value = row[field]
    if type(value) is not int:
        raise WebAnalysisLiveClaimJournalError(f"Live claim {field} is invalid")
    return value


def _required_dispatch_count(row: sqlite3.Row) -> Literal[0, 1]:
    value = _required_integer(row, "dispatch_count")
    if value not in {0, 1}:
        raise WebAnalysisLiveClaimJournalError("Live claim dispatch count is invalid")
    return cast(Literal[0, 1], value)


__all__ = [
    "DispatchStartedWebAnalysisLiveClaim",
    "ReservedWebAnalysisLiveClaim",
    "StartedWebAnalysisLiveClaim",
    "WebAnalysisLiveClaimBinding",
    "WebAnalysisLiveClaimGateDContext",
    "WebAnalysisLiveClaimJournal",
    "WebAnalysisLiveClaimJournalEntry",
    "WebAnalysisLiveClaimJournalError",
    "WebAnalysisLiveClaimPendingOutcome",
    "WebAnalysisLiveClaimPhase",
    "WebAnalysisLiveClaimResourceLocator",
    "WebAnalysisLiveClaimTerminalDisposition",
    "WebAnalysisLiveClaimTerminalPublication",
    "WebAnalysisOneCallAuthorizationCoordinate",
    "build_web_analysis_live_claim_binding",
]
