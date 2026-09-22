"""Cleanup-bound terminal receipts for the compact WEB-007 live runtime.

This is an additive v1alpha1 wire.  It deliberately does not import or accept
the historical ``[developer, user]`` invocation runtime, its request envelope,
or its receipts.  A receipt is written while the durable claim is still in
``pending-cleanup`` and is made authoritative for audit only when the claim
journal subsequently enters ``terminal`` and points back to the receipt digest.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Annotated, Final, Literal, Self, cast
from weakref import WeakKeyDictionary, WeakSet

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from pajin.benchmark.effectiveness.suite import RuntimePin
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel, ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import (
    RunIntegrityVerification,
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
    WebAnalysisCapacityV2Pin,
    WebAnalysisLiveModelCleanupOnlyResult,
    WebAnalysisLiveModelMaterializationAttestation,
    WebAnalysisLiveModelProviderRouteAttestation,
    WebAnalysisLiveModelResourceAbsenceProof,
)
from pajin.web_assessment.analysis_live_authorization import (
    SignedWebAnalysisOneCallAuthorization,
    VerifiedWebAnalysisOneCallAuthorization,
    WebAnalysisOneCallAuthorizationTrustAnchor,
    WebAnalysisOneCallAuthorizationVerifier,
)
from pajin.web_assessment.analysis_live_claim_journal import (
    VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
    WebAnalysisLiveClaimGateDContext,
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimJournalEntry,
    WebAnalysisLiveClaimJournalError,
    WebAnalysisLiveClaimPendingOutcome,
    WebAnalysisLiveClaimPhase,
    WebAnalysisLiveClaimTerminalDisposition,
    WebAnalysisLiveClaimTerminalPublication,
)
from pajin.web_assessment.analysis_skill_invocation import (
    CompiledSkillBoundWebAnalysisProposal,
    SkillBoundWebAnalysisProposalDraft,
    parse_skill_bound_web_analysis_proposal_draft,
    verify_compiled_skill_bound_web_analysis_proposal,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    plan_prepared_compact_skill_bound_web_analysis_admission,
    verify_planned_prepared_compact_skill_bound_web_analysis_admission,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    VerifiedCompactSkillBoundWebAnalysisPreparationRun,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillRegistryRef,
    VerifiedWebAnalysisSkillProjectionRun,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportCleanupProof,
    WebAnalysisTransportRuntimePin,
    expected_web_analysis_provider_worker_context,
    expected_web_analysis_transport_job_metadata,
    prepare_web_analysis_transport_job,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

COMPACT_LIVE_TERMINAL_RECEIPT_API_VERSION: Final = (
    "pajin.dev/compact-skill-bound-web-analysis-terminal-receipt/v1alpha1"
)
COMPACT_LIVE_TERMINAL_INDEX_API_VERSION: Final = (
    "pajin.dev/compact-skill-bound-web-analysis-terminal-index/v1alpha1"
)

_CAMPAIGN_PREFIX = "web-analysis-compact-live-terminal"
_RECEIPT_PATH = "compact-live-terminal-receipt.json"
_INDEX_PATH = "compact-live-terminal-index.json"
_AUTHORIZATION_PATH = "signed-one-call-authorization.json"
_DRAFT_PATH = "proposal-draft.json"
_PROPOSAL_PATH = "compiled-proposal.json"
_PublicationLoadMode = Literal["candidate", "anchored-pending", "terminal"]
_STARTED_EVENT = "web-analysis.compact-live-terminal.started"
_COMPLETED_EVENT = "web-analysis.compact-live-terminal.completed"
_ARTIFACT_PATHS = frozenset(
    {_RECEIPT_PATH, _INDEX_PATH, _AUTHORIZATION_PATH, _DRAFT_PATH, _PROPOSAL_PATH}
)
_MAX_RECEIPT_BYTES = 16 * 1024 * 1024
_MAX_INDEX_BYTES = 2 * 1024 * 1024
_MAX_AUTHORIZATION_BYTES = 512 * 1024
_MAX_DRAFT_BYTES = 512 * 1024
_MAX_PROPOSAL_BYTES = 8 * 1024 * 1024
_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_EXECUTION_ID_PATTERN = r"^exec_[a-f0-9]{32}$"
_LIVE_AGENT_ID: Final = "web-analysis-compact-live"
_MISSING_LIVE_ATTESTATION_STAGES: Final = frozenset(
    {
        "reservation",
        "live-start",
        "materialization",
        "materialization-attestation",
        "post-observation-recovery",
        "quiescent-recovery",
    }
)
_MISSING_PROVIDER_ROUTE_ATTESTATION_STAGES: Final = frozenset(
    {
        "reservation",
        "live-start",
        "materialization",
        "materialization-attestation",
        "pre-dispatch-revalidation",
        "post-observation-recovery",
        "quiescent-recovery",
    }
)
_NON_SUCCESS_FAILURE_STAGES: Final = {
    (WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED, 0): frozenset(
        {
            "reservation",
            "live-start",
            "materialization",
            "materialization-attestation",
            "pre-dispatch-revalidation",
            "quiescent-recovery",
        }
    ),
    (WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN, 0): frozenset(
        {
            "reservation",
            "live-start",
            "materialization",
            "materialization-attestation",
            "pre-dispatch-revalidation",
            "dispatch-marker",
            "quiescent-recovery",
        }
    ),
    (WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN, 1): frozenset(
        {
            "dispatch-marker",
            "dispatch",
            "post-observation-recovery",
            "quiescent-recovery",
        }
    ),
    (WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED, 1): frozenset(
        {
            "response-validation",
            "proposal-compilation",
            "post-observation-recovery",
            "quiescent-recovery",
        }
    ),
    (WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED, 1): frozenset(
        {"post-observation-recovery", "quiescent-recovery"}
    ),
}
_Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]


class CompactSkillBoundWebAnalysisTerminalReceiptError(RuntimeError):
    """Raised when a compact live terminal receipt fails closed."""


class _FrozenReceiptModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("compact live receipt verification markers must be literal true")
    return True


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("compact live receipt authority markers must be literal false")
    return False


def _digest(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii", errors="strict")
        + b"\x00"
        + canonical_json_bytes(
            value,
            label="compact live terminal receipt identity",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
    ).hexdigest()


def compact_skill_bound_web_analysis_lease_id(
    *,
    claim_digest: str,
    secret_ref: str,
    binding: str,
) -> str:
    """Return the sole credential lease identity allowed by the compact live contract."""

    material = canonical_json_bytes(
        {
            "claimDigest": claim_digest,
            "secretRefFingerprint": SecretBroker.fingerprint(secret_ref),
            "binding": binding,
        },
        label="compact live deterministic credential lease",
        max_bytes=8 * 1024,
    )
    digest = sha256(b"pajin.web-analysis.compact-live-lease/v1\x00" + material).hexdigest()
    return f"lease_{digest[:32]}"


def _strict_json_artifact_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _artifact_sha256(value: object) -> str:
    return sha256(_strict_json_artifact_bytes(value)).hexdigest()


def _terminal_disposition_for(
    outcome: WebAnalysisLiveClaimPendingOutcome,
    *,
    response_evidence_available: bool,
) -> WebAnalysisLiveClaimTerminalDisposition:
    if outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED:
        if response_evidence_available:
            return WebAnalysisLiveClaimTerminalDisposition.SUCCESS
        return WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    if outcome is WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED:
        return WebAnalysisLiveClaimTerminalDisposition.FAILURE
    return WebAnalysisLiveClaimTerminalDisposition.ABANDONED


def compact_skill_bound_web_analysis_terminal_run_id(
    pending_claim: WebAnalysisLiveClaimJournalEntry,
) -> str:
    """Return the sole legal terminal Run ID for one durable pending claim."""

    if (
        type(pending_claim) is not WebAnalysisLiveClaimJournalEntry
        or pending_claim.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
        or pending_claim.pending_outcome is None
    ):
        raise ValueError("terminal Run identity requires an exact pending-cleanup claim")
    timestamp = pending_claim.reserved_at
    compact_second = (
        f"{timestamp[0:4]}{timestamp[5:7]}{timestamp[8:10]}"
        f"T{timestamp[11:13]}{timestamp[14:16]}{timestamp[17:19]}Z"
    )
    run_id = f"run_{compact_second}_{pending_claim.binding.claim_digest[:8]}"
    if re.fullmatch(_RUN_ID_PATTERN, run_id) is None:
        raise ValueError("terminal Run identity construction failed closed")
    return run_id


def compact_skill_bound_web_analysis_terminal_run_path(
    output_root: Path,
    pending_claim: WebAnalysisLiveClaimJournalEntry,
) -> Path:
    """Return the only RunStore location allowed for one pending claim."""

    if not isinstance(output_root, Path):
        raise TypeError("terminal publication root must be a Path")
    return (
        output_root
        / f"{_CAMPAIGN_PREFIX}-{pending_claim.binding.claim_digest}"
        / compact_skill_bound_web_analysis_terminal_run_id(pending_claim)
    )


def require_compact_skill_bound_web_analysis_terminal_output_root(output_root: Path) -> Path:
    """Reject pre-existing symlinks before a terminal intent or Run can be written."""

    if not isinstance(output_root, Path):
        raise TypeError("terminal publication root must be a Path")
    absolute = Path(os.path.abspath(output_root))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("terminal publication root contains a symlink component")
    return absolute


def _require_trusted_terminal_run_path(
    run_path: Path,
    *,
    expected_output_root: Path,
    expected_run_id: str,
    expected_claim_digest: str,
) -> None:
    if not isinstance(run_path, Path) or not isinstance(expected_output_root, Path):
        raise TypeError("terminal Run path and trusted output root must be Paths")
    expected = (
        expected_output_root / f"{_CAMPAIGN_PREFIX}-{expected_claim_digest}" / expected_run_id
    )
    supplied_absolute = Path(os.path.abspath(run_path))
    expected_absolute = Path(os.path.abspath(expected))
    if supplied_absolute != expected_absolute:
        raise ValueError("terminal Run path is outside its trusted deterministic location")
    for candidate in (Path(os.path.abspath(expected_output_root)), supplied_absolute):
        current = Path(candidate.anchor)
        for component in candidate.parts[1:]:
            current /= component
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise ValueError("terminal Run trust path contains a symlink component")
    resolved_root = Path(os.path.abspath(expected_output_root)).resolve(strict=True)
    resolved_run = supplied_absolute.resolve(strict=True)
    resolved_expected = (
        resolved_root / f"{_CAMPAIGN_PREFIX}-{expected_claim_digest}" / expected_run_id
    )
    if resolved_run != resolved_expected:
        raise ValueError("terminal Run path traverses an untrusted symlink")
    if resolved_run != expected_absolute.resolve(strict=True):
        raise ValueError("terminal Run path normalization differs from its trusted location")


class CompactSkillBoundWebAnalysisDispatchObservation(_FrozenReceiptModel):
    """Secret-free observation of the sole dispatch slot and its outcome."""

    api_version: Literal[
        "pajin.dev/compact-skill-bound-web-analysis-dispatch-observation/v1alpha1"
    ] = Field(
        default="pajin.dev/compact-skill-bound-web-analysis-dispatch-observation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CompactSkillBoundWebAnalysisDispatchObservation"] = (
        "CompactSkillBoundWebAnalysisDispatchObservation"
    )
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    provider_id: str = Field(alias="providerId", pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    transport_execution_id: str = Field(alias="transportExecutionId", pattern=_EXECUTION_ID_PATTERN)
    transport_binding_digest: _Sha256 = Field(alias="transportBindingDigest")
    transport_worker_context_digest: _Sha256 = Field(alias="transportWorkerContextDigest")
    transport_job_metadata_digest: _Sha256 = Field(alias="transportJobMetadataDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    pending_outcome: WebAnalysisLiveClaimPendingOutcome = Field(alias="pendingOutcome")
    dispatch_count: Literal[0, 1] = Field(alias="dispatchCount")
    response_sha256: _Sha256 | None = Field(default=None, alias="responseSha256")
    response_bytes: int = Field(default=0, alias="responseBytes", ge=0, le=4_000_000)
    response_evidence_available: bool = Field(alias="responseEvidenceAvailable")
    failure_digest: _Sha256 | None = Field(default=None, alias="failureDigest")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")
    tool_call_count: Literal[0] = Field(default=0, alias="toolCallCount")
    streamed: Literal[False] = False
    automatic_redispatch_performed: Literal[False] = Field(
        default=False, alias="automaticRedispatchPerformed"
    )

    @field_validator(
        "dispatch_count", "response_bytes", "target_request_count", "tool_call_count", mode="before"
    )
    @classmethod
    def require_integer_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("compact live dispatch counts must be exact JSON integers")
        return value

    @field_validator("streamed", "automatic_redispatch_performed", mode="before")
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("response_evidence_available", mode="before")
    @classmethod
    def require_literal_response_evidence_marker(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("response evidence availability must be a literal JSON boolean")
        return value

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        has_response = self.response_sha256 is not None
        if (
            has_response != (self.response_bytes > 0)
            or has_response != self.response_evidence_available
        ):
            raise ValueError("compact live dispatch response binding differs")
        if self.pending_outcome is WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED:
            if self.dispatch_count != 0 or has_response or self.failure_digest is None:
                raise ValueError("not-dispatched observation consumed a dispatch or response")
        elif self.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED:
            if self.dispatch_count != 1:
                raise ValueError("successful dispatch observation is incomplete")
            if has_response == (self.failure_digest is not None):
                raise ValueError("successful dispatch response retention state differs")
        elif self.pending_outcome is WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED:
            if self.dispatch_count != 1 or has_response or self.failure_digest is None:
                raise ValueError("failed dispatch observation is incomplete")
        elif self.pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN and (
            has_response or self.failure_digest is None
        ):
            raise ValueError("uncertain dispatch observation requires a failure digest")
        material = self.model_dump(mode="json", by_alias=True, exclude={"observation_digest"})
        digest = _digest("pajin.web-analysis.compact-live-dispatch-observation/v1", material)
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("compact live dispatch observation digest differs")
        object.__setattr__(self, "observation_digest", digest)
        return self


class CompactSkillBoundWebAnalysisTransportBinding(_FrozenReceiptModel):
    """Exact reconstructable Worker context and job metadata for the selected transport."""

    api_version: Literal[
        "pajin.dev/compact-skill-bound-web-analysis-transport-binding/v1alpha1"
    ] = Field(
        default="pajin.dev/compact-skill-bound-web-analysis-transport-binding/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CompactSkillBoundWebAnalysisTransportBinding"] = (
        "CompactSkillBoundWebAnalysisTransportBinding"
    )
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    runtime_pin: RuntimePin = Field(alias="runtimePin")
    tool_request: ToolRequest = Field(alias="toolRequest")
    provider_registration: ProviderRegistration = Field(alias="providerRegistration")
    transport_pin: WebAnalysisTransportRuntimePin = Field(alias="transportPin")
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    live_claim_digest: _Sha256 = Field(alias="liveClaimDigest")
    transport_execution_id: str = Field(alias="transportExecutionId", pattern=_EXECUTION_ID_PATTERN)
    external_network: str = Field(
        alias="externalNetwork",
        pattern=r"^pajin-web-analysis-live-network-[a-f0-9]{32}$",
    )
    lease_ids: tuple[Annotated[str, Field(pattern=r"^lease_[a-f0-9]{32}$")], ...] = Field(
        default=(), alias="leaseIds", max_length=1
    )
    worker_context: dict[str, JsonValue] = Field(alias="workerContext")
    worker_context_digest: str = Field(default="", alias="workerContextDigest", max_length=64)
    job_metadata: dict[str, JsonValue] = Field(alias="jobMetadata")
    job_metadata_digest: str = Field(default="", alias="jobMetadataDigest", max_length=64)
    secret_material_embedded: Literal[False] = Field(default=False, alias="secretMaterialEmbedded")
    external_egress_authority: Literal[False] = Field(
        default=False, alias="externalEgressAuthority"
    )

    @field_validator("secret_material_embedded", "external_egress_authority", mode="before")
    @classmethod
    def require_no_secret_or_egress_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_transport(self) -> Self:
        if (
            self.transport_pin.pin_digest != self.transport_pin_digest
            or self.tool_request.agent_id != _LIVE_AGENT_ID
            or self.tool_request.method != "POST"
            or self.tool_request.target != str(self.provider_registration.endpoint)
            or self.tool_request.tool_id
            != f"provider.{self.provider_registration.provider_id}.chat"
        ):
            raise ValueError("compact live transport binding Pin digest differs")
        ProviderChatRequest.model_validate(self.tool_request.arguments)
        expected_context = expected_web_analysis_provider_worker_context(
            self.transport_pin,
            external_network=self.external_network,
            claim_digest=self.live_claim_digest,
            execution_id=self.transport_execution_id,
        )
        expected_metadata = expected_web_analysis_transport_job_metadata(
            self.tool_request,
            registration=self.provider_registration,
            runtime=self.runtime_pin,
            transport_pin=self.transport_pin,
            expected_transport_pin_digest=self.transport_pin.pin_digest,
            execution_id=self.transport_execution_id,
            lease_ids=list(self.lease_ids),
        )
        context_wire = canonical_json_bytes(
            self.worker_context,
            label="compact live transport Worker context",
            max_bytes=2 * 1024 * 1024,
        )
        expected_context_wire = canonical_json_bytes(
            expected_context,
            label="expected compact live transport Worker context",
            max_bytes=2 * 1024 * 1024,
        )
        metadata_wire = canonical_json_bytes(
            self.job_metadata,
            label="compact live transport job metadata",
            max_bytes=2 * 1024 * 1024,
        )
        expected_metadata_wire = canonical_json_bytes(
            expected_metadata,
            label="expected compact live transport job metadata",
            max_bytes=2 * 1024 * 1024,
        )
        if context_wire != expected_context_wire or metadata_wire != expected_metadata_wire:
            raise ValueError("compact live transport context or job metadata differs")
        context_digest = sha256(context_wire).hexdigest()
        metadata_digest = sha256(metadata_wire).hexdigest()
        if self.worker_context_digest and self.worker_context_digest != context_digest:
            raise ValueError("compact live transport Worker context digest differs")
        if self.job_metadata_digest and self.job_metadata_digest != metadata_digest:
            raise ValueError("compact live transport job metadata digest differs")
        object.__setattr__(self, "worker_context_digest", context_digest)
        object.__setattr__(self, "job_metadata_digest", metadata_digest)
        material = self.model_dump(mode="json", by_alias=True, exclude={"binding_digest"})
        binding_digest = _digest("pajin.web-analysis.compact-live-transport-binding/v1", material)
        if self.binding_digest and self.binding_digest != binding_digest:
            raise ValueError("compact live transport binding digest differs")
        object.__setattr__(self, "binding_digest", binding_digest)
        return self


def _expected_transport_binding_lease_id(
    transport: CompactSkillBoundWebAnalysisTransportBinding,
) -> str:
    job = prepare_web_analysis_transport_job(
        transport.tool_request,
        registration=transport.provider_registration,
        runtime=transport.runtime_pin,
        transport_pin=transport.transport_pin,
        expected_transport_pin_digest=transport.transport_pin_digest,
        execution_id=transport.transport_execution_id,
    )
    if len(job.secret_requests) != 1:
        raise ValueError("compact live transport requires exactly one credential request")
    request = job.secret_requests[0]
    return compact_skill_bound_web_analysis_lease_id(
        claim_digest=transport.live_claim_digest,
        secret_ref=request.secret_ref,
        binding=request.binding,
    )


class CompactSkillBoundWebAnalysisCleanupResult(_FrozenReceiptModel):
    """Aggregate model and transport cleanup with an independent absence digest."""

    api_version: Literal["pajin.dev/compact-skill-bound-web-analysis-cleanup-result/v1alpha1"] = (
        Field(
            default="pajin.dev/compact-skill-bound-web-analysis-cleanup-result/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["CompactSkillBoundWebAnalysisCleanupResult"] = (
        "CompactSkillBoundWebAnalysisCleanupResult"
    )
    cleanup_digest: str = Field(default="", alias="cleanupDigest", max_length=64)
    resource_absence_digest: str = Field(default="", alias="resourceAbsenceDigest", max_length=64)
    claim_store_id: _Sha256 = Field(alias="claimStoreId")
    claim_digest: _Sha256 = Field(alias="claimDigest")
    pending_claim_state_digest: _Sha256 = Field(alias="pendingClaimStateDigest")
    dispatch_observation_digest: _Sha256 = Field(alias="dispatchObservationDigest")
    live_attestation_digest: _Sha256 | None = Field(default=None, alias="liveAttestationDigest")
    provider_route_attestation_digest: _Sha256 | None = Field(
        default=None,
        alias="providerRouteAttestationDigest",
    )
    model_cleanup: WebAnalysisLiveModelCleanupOnlyResult = Field(alias="modelCleanup")
    model_absence: WebAnalysisLiveModelResourceAbsenceProof = Field(alias="modelAbsence")
    transport_cleanup: WebAnalysisTransportCleanupProof = Field(alias="transportCleanup")
    revoked_lease_ids: tuple[Annotated[str, Field(pattern=r"^lease_[a-f0-9]{32}$")], ...] = Field(
        default=(), alias="revokedLeaseIds", max_length=1
    )
    credential_leases_revoked: Literal[True] = Field(alias="credentialLeasesRevoked")
    all_owned_resources_removed_or_absent: Literal[True] = Field(
        alias="allOwnedResourcesRemovedOrAbsent"
    )
    aggregate_absence_verified: Literal[True] = Field(alias="aggregateAbsenceVerified")

    @field_validator(
        "all_owned_resources_removed_or_absent",
        "aggregate_absence_verified",
        "credential_leases_revoked",
        mode="before",
    )
    @classmethod
    def require_cleanup_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @model_validator(mode="after")
    def bind_cleanup(self) -> Self:
        model = self.model_cleanup
        absence = self.model_absence
        transport = self.transport_cleanup
        if (
            model.resource_owner != absence.resource_owner
            or model.absence_proof_digest != absence.proof_digest
            or (
                model.runtime_container_name,
                model.seed_container_name,
                model.volume_name,
                model.network_name,
            )
            != (
                absence.runtime_container_name,
                absence.seed_container_name,
                absence.volume_name,
                absence.network_name,
            )
        ):
            raise ValueError("aggregate compact live cleanup ownership differs")
        absence_digest = _digest(
            "pajin.web-analysis.compact-live-aggregate-absence/v1",
            {
                "resourceOwner": model.resource_owner,
                "claimStoreId": self.claim_store_id,
                "claimDigest": self.claim_digest,
                "pendingClaimStateDigest": self.pending_claim_state_digest,
                "dispatchObservationDigest": self.dispatch_observation_digest,
                "liveAttestationDigest": self.live_attestation_digest,
                "providerRouteAttestationDigest": self.provider_route_attestation_digest,
                "modelAbsenceDigest": absence.proof_digest,
                "transportAbsenceDigest": transport.resource_absence_digest,
                "revokedLeaseIds": list(self.revoked_lease_ids),
                "credentialLeasesRevoked": True,
            },
        )
        if self.resource_absence_digest and self.resource_absence_digest != absence_digest:
            raise ValueError("aggregate compact live absence digest differs")
        object.__setattr__(self, "resource_absence_digest", absence_digest)
        material = self.model_dump(mode="json", by_alias=True, exclude={"cleanup_digest"})
        digest = _digest("pajin.web-analysis.compact-live-cleanup-result/v1", material)
        if self.cleanup_digest and self.cleanup_digest != digest:
            raise ValueError("aggregate compact live cleanup digest differs")
        object.__setattr__(self, "cleanup_digest", digest)
        return self


class CompactSkillBoundWebAnalysisTerminalReceipt(_FrozenReceiptModel):
    """Pending-state receipt sealed before the journal terminal cross-link."""

    api_version: Literal["pajin.dev/compact-skill-bound-web-analysis-terminal-receipt/v1alpha1"] = (
        Field(default=COMPACT_LIVE_TERMINAL_RECEIPT_API_VERSION, alias="apiVersion")
    )
    kind: Literal["CompactSkillBoundWebAnalysisTerminalReceipt"] = (
        "CompactSkillBoundWebAnalysisTerminalReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    terminal_run_id: str = Field(alias="terminalRunId", pattern=_RUN_ID_PATTERN)
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope
    capacity_pin: WebAnalysisCapacityV2Pin = Field(alias="capacityPin")
    transport_pin: WebAnalysisTransportRuntimePin = Field(alias="transportPin")
    signed_authorization: SignedWebAnalysisOneCallAuthorization = Field(alias="signedAuthorization")
    initial_authorization_verification: VerifiedWebAnalysisOneCallAuthorization = Field(
        alias="initialAuthorizationVerification"
    )
    pre_dispatch_authorization_verification: VerifiedWebAnalysisOneCallAuthorization | None = Field(
        default=None, alias="preDispatchAuthorizationVerification"
    )
    claim_store_id: _Sha256 = Field(alias="claimStoreId")
    gate_d_context_digest: _Sha256 = Field(alias="gateDContextDigest")
    pending_claim: WebAnalysisLiveClaimJournalEntry = Field(alias="pendingClaim")
    live_materialization_attestation: WebAnalysisLiveModelMaterializationAttestation | None = Field(
        default=None, alias="liveMaterializationAttestation"
    )
    provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation | None = Field(
        default=None,
        alias="providerRouteAttestation",
    )
    provider_registration: ProviderRegistration = Field(alias="providerRegistration")
    provider_chat_request: ProviderChatRequest = Field(alias="providerChatRequest")
    transport_binding: CompactSkillBoundWebAnalysisTransportBinding = Field(
        alias="transportBinding"
    )
    transport_execution_id: str = Field(alias="transportExecutionId", pattern=_EXECUTION_ID_PATTERN)
    dispatch_observation: CompactSkillBoundWebAnalysisDispatchObservation = Field(
        alias="dispatchObservation"
    )
    cleanup_result: CompactSkillBoundWebAnalysisCleanupResult = Field(alias="cleanupResult")
    draft: SkillBoundWebAnalysisProposalDraft | None = None
    compiled_proposal: CompiledSkillBoundWebAnalysisProposal | None = Field(
        default=None, alias="compiledProposal"
    )
    intended_terminal_disposition: WebAnalysisLiveClaimTerminalDisposition = Field(
        alias="intendedTerminalDisposition"
    )
    failure_stage: (
        Literal[
            "reservation",
            "live-start",
            "materialization",
            "materialization-attestation",
            "pre-dispatch-revalidation",
            "dispatch-marker",
            "dispatch",
            "response-validation",
            "proposal-compilation",
            "post-observation-recovery",
            "quiescent-recovery",
            "terminal-publication",
        ]
        | None
    ) = Field(default=None, alias="failureStage")
    failure_digest: _Sha256 | None = Field(default=None, alias="failureDigest")
    cleanup_bound: Literal[True] = Field(alias="cleanupBound")
    terminal_journal_cross_link_required: Literal[True] = Field(
        alias="terminalJournalCrossLinkRequired"
    )
    target_request_authority: Literal[False] = Field(alias="targetRequestAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    report_authority: Literal[False] = Field(alias="reportAuthority")
    delivery_authority: Literal[False] = Field(alias="deliveryAuthority")
    retry_authority: Literal[False] = Field(alias="retryAuthority")
    automatic_redispatch_authority: Literal[False] = Field(alias="automaticRedispatchAuthority")

    @field_validator("cleanup_bound", "terminal_journal_cross_link_required", mode="before")
    @classmethod
    def require_true_markers(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator(
        "target_request_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "finding_authority",
        "graph_admission_authority",
        "report_authority",
        "delivery_authority",
        "retry_authority",
        "automatic_redispatch_authority",
        mode="before",
    )
    @classmethod
    def require_no_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    def _validate_terminal_evidence(
        self,
        *,
        claim: WebAnalysisLiveClaimJournalEntry,
        before_dispatch: VerifiedWebAnalysisOneCallAuthorization | None,
        attestation: WebAnalysisLiveModelMaterializationAttestation | None,
        provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation | None,
        observation: CompactSkillBoundWebAnalysisDispatchObservation,
    ) -> None:
        success = (
            self.intended_terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.SUCCESS
        )
        if self.intended_terminal_disposition is not _terminal_disposition_for(
            cast(WebAnalysisLiveClaimPendingOutcome, claim.pending_outcome),
            response_evidence_available=observation.response_evidence_available,
        ):
            raise ValueError("compact live terminal disposition differs from pending outcome")
        if success:
            draft_wire = (
                b""
                if self.draft is None
                else canonical_json_bytes(
                    self.draft.model_dump(mode="json", by_alias=True),
                    label="compact live retained response draft",
                    max_bytes=_MAX_DRAFT_BYTES,
                )
            )
            if (
                claim.pending_outcome is not WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
                or claim.dispatch_count != 1
                or before_dispatch is None
                or attestation is None
                or provider_route_attestation is None
                or observation.response_evidence_available is not True
                or self.draft is None
                or self.compiled_proposal is None
                or self.failure_stage is not None
                or self.failure_digest is not None
                or observation.response_sha256 != sha256(draft_wire).hexdigest()
                or observation.response_bytes != len(draft_wire)
            ):
                raise ValueError("compact live terminal success lacks proposal evidence")
        elif (
            self.draft is not None
            or self.compiled_proposal is not None
            or self.failure_stage is None
            or self.failure_digest is None
            or observation.failure_digest is None
            or observation.failure_digest != self.failure_digest
        ):
            raise ValueError("non-success compact live receipt failure binding differs")
        if not success:
            allowed_stages = _NON_SUCCESS_FAILURE_STAGES.get(
                (
                    cast(WebAnalysisLiveClaimPendingOutcome, claim.pending_outcome),
                    claim.dispatch_count,
                )
            )
            if allowed_stages is None or self.failure_stage not in allowed_stages:
                raise ValueError(
                    "compact live failure stage differs from outcome and dispatch count"
                )
            if (
                claim.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
                and observation.response_evidence_available is not False
            ):
                raise ValueError("observed-success recovery retained ambiguous response evidence")
        if (
            claim.dispatch_count == 1
            and attestation is None
            and self.failure_stage not in {"post-observation-recovery", "quiescent-recovery"}
        ):
            raise ValueError("dispatched compact live receipt lacks materialization evidence")
        if claim.dispatch_count == 1 and before_dispatch is None:
            raise ValueError("dispatched compact live receipt lacks durable pre-dispatch evidence")
        if attestation is None and self.failure_stage not in _MISSING_LIVE_ATTESTATION_STAGES:
            raise ValueError("compact live receipt omits required materialization attestation")
        if (
            provider_route_attestation is None
            and self.failure_stage not in _MISSING_PROVIDER_ROUTE_ATTESTATION_STAGES
        ):
            raise ValueError("compact live receipt omits required Provider route attestation")
        if (
            provider_route_attestation is None
            and self.failure_stage
            not in {
                "post-observation-recovery",
                "quiescent-recovery",
            }
            and self.cleanup_result.provider_route_attestation_digest is not None
        ):
            raise ValueError("compact live receipt carries unrecorded Provider route evidence")

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        admission = self.admission
        claim = self.pending_claim
        binding = claim.binding
        signed = self.signed_authorization
        initial = self.initial_authorization_verification
        before_dispatch = self.pre_dispatch_authorization_verification
        attestation = self.live_materialization_attestation
        provider_route_attestation = self.provider_route_attestation
        observation = self.dispatch_observation
        cleanup = self.cleanup_result
        transport_binding = self.transport_binding
        registration = self.provider_registration
        if (
            claim.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
            or claim.pending_outcome is None
            or claim.terminal_at is not None
            or claim.terminal_disposition is not None
            or claim.cleanup_result_digest is not None
            or claim.resource_absence_digest is not None
            or claim.terminal_receipt_digest is not None
            or self.terminal_run_id != compact_skill_bound_web_analysis_terminal_run_id(claim)
            or binding.admission_digest != admission.admission_digest
            or binding.preparation_identity != admission.preparation_digest
            or binding.preparation_run_id != admission.preparation_run_id
            or binding.preparation_run_root_digest != admission.preparation_run_root_digest
            or binding.preparation_index_digest != admission.preparation_index_digest
            or binding.live_request_digest != admission.live_request_digest
            or binding.capacity_pin_digest != admission.capacity_pin_digest
            or binding.transport_pin_digest != admission.transport_pin_digest
            or binding.provider_registration_digest != admission.provider_registration_digest
            or binding.provider_chat_request_digest != admission.provider_chat_request_digest
            or binding.compact_projection_digest != admission.compact_projection_digest
            or binding.response_schema_digest != admission.response_schema_digest
        ):
            raise ValueError("compact live receipt pending claim differs from admission")
        if (
            signed.digest != binding.authorization_envelope_digest
            or initial.authorization_envelope_digest != signed.digest
            or initial.coordinate.coordinate_digest != binding.authorization_coordinate_digest
            or initial.coordinate.authorization_identity != binding.authorization_identity
            or initial.admission_digest != admission.admission_digest
            or initial.preparation_identity != admission.preparation_digest
            or initial.live_request_digest != admission.live_request_digest
        ):
            raise ValueError("compact live receipt authorization lineage differs")
        reserved_at = _claim_timestamp(claim.reserved_at)
        if initial.evaluated_at > reserved_at or reserved_at >= initial.expires_at:
            raise ValueError("compact live initial authorization time differs")
        if before_dispatch is not None and (
            before_dispatch.authorization_envelope_digest != signed.digest
            or initial.coordinate != before_dispatch.coordinate
            or initial.trust_anchor_digest != before_dispatch.trust_anchor_digest
            or before_dispatch.admission_digest != admission.admission_digest
            or before_dispatch.preparation_identity != admission.preparation_digest
            or before_dispatch.live_request_digest != admission.live_request_digest
            or before_dispatch.evaluated_at <= initial.evaluated_at
        ):
            raise ValueError("compact live pre-dispatch authorization lineage differs")
        if before_dispatch is not None:
            live_started_at = claim.live_started_at
            pre_dispatch_upper_bound = claim.dispatch_started_at or claim.pending_cleanup_at
            if (
                live_started_at is None
                or pre_dispatch_upper_bound is None
                or before_dispatch.evaluated_at < _claim_timestamp(live_started_at)
                or before_dispatch.evaluated_at > _claim_timestamp(pre_dispatch_upper_bound)
                or (
                    claim.dispatch_started_at is not None
                    and before_dispatch.expires_at <= _claim_timestamp(claim.dispatch_started_at)
                )
            ):
                raise ValueError("compact live pre-dispatch authorization time differs")
        resources = binding.resources
        if (
            self.capacity_pin.pin_digest != admission.capacity_pin_digest
            or self.transport_pin.pin_digest != admission.transport_pin_digest
        ):
            raise ValueError("compact live receipt materialization lineage differs")
        if attestation is not None and (
            attestation.capacity_run_id != admission.capacity_run_id
            or attestation.capacity_root_digest != admission.capacity_run_root_digest
            or attestation.capacity_pin_digest != admission.capacity_pin_digest
            or attestation.capacity_proof_digest != admission.capacity_proof_digest
            or attestation.capacity_materialization_attestation_digest
            != admission.model_materialization_attestation_digest
            or attestation.model_pin_digest != self.capacity_pin.model_pin_digest
            or attestation.resource_owner != resources.resource_owner
            or attestation.runtime_container_name != resources.runtime_container_name
            or attestation.volume_name != resources.volume_name
            or attestation.network_name != resources.network_name
        ):
            raise ValueError("compact live receipt materialization attestation differs")
        if provider_route_attestation is not None and (
            attestation is None
            or provider_route_attestation.claim_digest != binding.claim_digest
            or provider_route_attestation.resource_owner != resources.resource_owner
            or provider_route_attestation.live_materialization_attestation_digest
            != attestation.attestation_digest
            or provider_route_attestation.runtime_container_name
            != attestation.runtime_container_name
            or provider_route_attestation.runtime_container_id != attestation.runtime_container_id
            or provider_route_attestation.network_name != attestation.network_name
            or provider_route_attestation.network_id != attestation.network_id
            or provider_route_attestation.provider_registration_digest
            != admission.provider_registration_digest
            or provider_route_attestation.provider_endpoint != str(registration.endpoint)
        ):
            raise ValueError("compact live receipt Provider route attestation differs")
        if transport_binding.lease_ids or before_dispatch is not None or claim.dispatch_count == 1:
            expected_lease_id = _expected_transport_binding_lease_id(transport_binding)
            if transport_binding.lease_ids != (expected_lease_id,) or cleanup.revoked_lease_ids != (
                expected_lease_id,
            ):
                raise ValueError("compact live receipt credential lease identity differs")
        if (
            registration.provider_id != signed.statement.provider_id
            or registration.model != signed.statement.model_id
            or observation.provider_id != registration.provider_id
            or observation.model_id != registration.model
            or observation.provider_registration_digest != admission.provider_registration_digest
            or observation.provider_chat_request_digest != admission.provider_chat_request_digest
            or self.transport_execution_id != f"exec_{resources.resource_owner}"
            or observation.transport_execution_id != self.transport_execution_id
            or observation.transport_binding_digest != transport_binding.binding_digest
            or observation.transport_worker_context_digest
            != transport_binding.worker_context_digest
            or observation.transport_job_metadata_digest != transport_binding.job_metadata_digest
            or transport_binding.provider_registration != registration
            or transport_binding.transport_pin != self.transport_pin
            or transport_binding.transport_pin_digest != self.transport_pin.pin_digest
            or transport_binding.live_claim_digest != binding.claim_digest
            or transport_binding.transport_execution_id != self.transport_execution_id
            or transport_binding.external_network != resources.network_name
            or transport_binding.tool_request.request_id != f"tool_{resources.resource_owner}"
            or transport_binding.tool_request.agent_id != _LIVE_AGENT_ID
            or ProviderChatRequest.model_validate(transport_binding.tool_request.arguments)
            != self.provider_chat_request
            or transport_binding.tool_request.method != "POST"
            or transport_binding.tool_request.target != str(registration.endpoint)
            or transport_binding.tool_request.tool_id != f"provider.{registration.provider_id}.chat"
            or cleanup.transport_cleanup.execution_id != self.transport_execution_id
            or cleanup.transport_cleanup.transport_pin_digest != self.transport_pin.pin_digest
            or cleanup.transport_cleanup.external_network != resources.network_name
            or cleanup.revoked_lease_ids != transport_binding.lease_ids
            or cleanup.model_cleanup.resource_owner != resources.resource_owner
            or cleanup.claim_store_id != self.claim_store_id
            or cleanup.claim_digest != binding.claim_digest
            or cleanup.pending_claim_state_digest != claim.state_digest
            or cleanup.dispatch_observation_digest != observation.observation_digest
            or cleanup.live_attestation_digest
            != (None if attestation is None else attestation.attestation_digest)
            or (
                provider_route_attestation is not None
                and cleanup.provider_route_attestation_digest
                != provider_route_attestation.attestation_digest
            )
            or observation.pending_outcome is not claim.pending_outcome
            or observation.dispatch_count != claim.dispatch_count
        ):
            raise ValueError("compact live receipt request, dispatch, or cleanup differs")
        self._validate_terminal_evidence(
            claim=claim,
            before_dispatch=before_dispatch,
            attestation=attestation,
            provider_route_attestation=provider_route_attestation,
            observation=observation,
        )
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"receipt_id", "receipt_digest"}
        )
        digest = _digest("pajin.web-analysis.compact-live-terminal-receipt/v1", material)
        receipt_id = f"compact-live-web-analysis-terminal:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("compact live terminal receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("compact live terminal receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class CompactSkillBoundWebAnalysisTerminalIndex(_FrozenReceiptModel):
    """Content-addressed inventory for one fixed terminal Run layout."""

    api_version: Literal["pajin.dev/compact-skill-bound-web-analysis-terminal-index/v1alpha1"] = (
        Field(default=COMPACT_LIVE_TERMINAL_INDEX_API_VERSION, alias="apiVersion")
    )
    kind: Literal["CompactSkillBoundWebAnalysisTerminalIndex"] = (
        "CompactSkillBoundWebAnalysisTerminalIndex"
    )
    index_digest: str = Field(default="", alias="indexDigest", max_length=64)
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    receipt_path: Literal["compact-live-terminal-receipt.json"] = Field(alias="receiptPath")
    receipt_digest: _Sha256 = Field(alias="receiptDigest")
    receipt_artifact_sha256: _Sha256 = Field(alias="receiptArtifactSha256")
    authorization_path: Literal["signed-one-call-authorization.json"] = Field(
        alias="authorizationPath"
    )
    authorization_envelope_digest: _Sha256 = Field(alias="authorizationEnvelopeDigest")
    authorization_artifact_sha256: _Sha256 = Field(alias="authorizationArtifactSha256")
    draft_path: Literal["proposal-draft.json"] = Field(alias="draftPath")
    draft_artifact_sha256: _Sha256 = Field(alias="draftArtifactSha256")
    proposal_path: Literal["compiled-proposal.json"] = Field(alias="proposalPath")
    proposal_artifact_sha256: _Sha256 = Field(alias="proposalArtifactSha256")
    claim_store_id: _Sha256 = Field(alias="claimStoreId")
    claim_digest: _Sha256 = Field(alias="claimDigest")
    gate_d_context_digest: _Sha256 = Field(alias="gateDContextDigest")
    pending_claim_state_digest: _Sha256 = Field(alias="pendingClaimStateDigest")
    cleanup_result_digest: _Sha256 = Field(alias="cleanupResultDigest")
    resource_absence_digest: _Sha256 = Field(alias="resourceAbsenceDigest")
    provider_route_attestation_digest: _Sha256 | None = Field(
        default=None,
        alias="providerRouteAttestationDigest",
    )
    intended_terminal_disposition: WebAnalysisLiveClaimTerminalDisposition = Field(
        alias="intendedTerminalDisposition"
    )

    @model_validator(mode="after")
    def bind_index(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"index_digest"})
        digest = _digest("pajin.web-analysis.compact-live-terminal-index/v1", material)
        if self.index_digest and self.index_digest != digest:
            raise ValueError("compact live terminal Index digest differs")
        object.__setattr__(self, "index_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisTerminalPublication:
    """Independent anchors for one sealed compact live terminal Run."""

    run_path: Path
    run_id: str
    root_digest: str


@dataclass(frozen=True, slots=True)
class VerifiedCompactSkillBoundWebAnalysisTerminalRun:
    """Audit-safe terminal result; proposal is exposed only for terminal success."""

    run_path: Path
    verification: RunIntegrityVerification
    index: CompactSkillBoundWebAnalysisTerminalIndex
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt
    signed_authorization: SignedWebAnalysisOneCallAuthorization
    gate_d_context: WebAnalysisLiveClaimGateDContext
    draft: SkillBoundWebAnalysisProposalDraft | None
    proposal: CompiledSkillBoundWebAnalysisProposal | None
    terminal_claim: WebAnalysisLiveClaimJournalEntry
    semantics: Literal["cleanup-bound-terminal-audit-not-downstream-authority"] = (
        "cleanup-bound-terminal-audit-not-downstream-authority"
    )
    target_request_authority: Literal[False] = False
    tool_request_authority: Literal[False] = False
    finding_authority: Literal[False] = False
    graph_admission_authority: Literal[False] = False
    report_authority: Literal[False] = False
    retry_authority: Literal[False] = False
    automatic_redispatch_authority: Literal[False] = False


@dataclass(frozen=True, slots=True)
class VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
    """Finalize-only view of an existing seal; it exposes no proposal payload."""

    run_path: Path
    run_id: str
    root_digest: str
    verification: RunIntegrityVerification
    receipt_digest: str
    gate_d_context_digest: str
    cleanup_result_digest: str
    resource_absence_digest: str
    live_attestation_digest: str | None
    provider_route_attestation_digest: str | None
    intended_terminal_disposition: WebAnalysisLiveClaimTerminalDisposition
    pending_claim: WebAnalysisLiveClaimJournalEntry
    verified_candidate: VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate | None = None
    proposal_exposed: Literal[False] = False
    provider_dispatch_authority: Literal[False] = False
    automatic_redispatch_authority: Literal[False] = False


@dataclass(frozen=True, slots=True)
class _VerifiedTerminalPublicationCandidateState:
    journal: WebAnalysisLiveClaimJournal
    claim_id: str
    intent_digest: str
    root_digest: str


_VERIFIED_TERMINAL_PUBLICATION_CANDIDATES: WeakKeyDictionary[
    VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
    _VerifiedTerminalPublicationCandidateState,
] = WeakKeyDictionary()
_CONSUMED_TERMINAL_PUBLICATION_CANDIDATES: WeakSet[
    VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate
] = WeakSet()
_TERMINAL_PUBLICATION_CANDIDATE_LOCK = Lock()


def _peek_verified_terminal_publication_candidate(
    candidate: VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
) -> tuple[str, str, str]:
    if type(candidate) is not VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate:
        raise WebAnalysisLiveClaimJournalError(
            "Verified terminal publication candidate was not strict-loader-issued"
        )
    with _TERMINAL_PUBLICATION_CANDIDATE_LOCK:
        state = _VERIFIED_TERMINAL_PUBLICATION_CANDIDATES.get(candidate)
        if state is None or candidate in _CONSUMED_TERMINAL_PUBLICATION_CANDIDATES:
            raise WebAnalysisLiveClaimJournalError(
                "Verified terminal publication candidate is foreign or consumed"
            )
        return state.claim_id, state.intent_digest, state.root_digest


def _take_verified_terminal_publication_candidate(
    candidate: VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
    *,
    journal: WebAnalysisLiveClaimJournal,
) -> tuple[str, str, str]:
    with _TERMINAL_PUBLICATION_CANDIDATE_LOCK:
        state = _VERIFIED_TERMINAL_PUBLICATION_CANDIDATES.get(candidate)
        if (
            type(candidate) is not VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate
            or state is None
            or candidate in _CONSUMED_TERMINAL_PUBLICATION_CANDIDATES
        ):
            raise WebAnalysisLiveClaimJournalError(
                "Verified terminal publication candidate is foreign or consumed"
            )
        if state.journal is not journal:
            raise WebAnalysisLiveClaimJournalError(
                "Verified terminal publication candidate is foreign or consumed"
            )
        _CONSUMED_TERMINAL_PUBLICATION_CANDIDATES.add(candidate)
        return state.claim_id, state.intent_digest, state.root_digest


def _index_for(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
    signed_authorization: SignedWebAnalysisOneCallAuthorization,
    draft: SkillBoundWebAnalysisProposalDraft | None,
    proposal: CompiledSkillBoundWebAnalysisProposal | None,
) -> CompactSkillBoundWebAnalysisTerminalIndex:
    receipt_wire = receipt.model_dump(mode="json", by_alias=True)
    authorization_wire = signed_authorization.model_dump(mode="json", by_alias=True)
    draft_wire = None if draft is None else draft.model_dump(mode="json", by_alias=True)
    proposal_wire = None if proposal is None else proposal.model_dump(mode="json", by_alias=True)
    return CompactSkillBoundWebAnalysisTerminalIndex(
        indexDigest="",
        runId=receipt.terminal_run_id,
        receiptPath="compact-live-terminal-receipt.json",
        receiptDigest=receipt.receipt_digest,
        receiptArtifactSha256=_artifact_sha256(receipt_wire),
        authorizationPath="signed-one-call-authorization.json",
        authorizationEnvelopeDigest=signed_authorization.digest,
        authorizationArtifactSha256=_artifact_sha256(authorization_wire),
        draftPath="proposal-draft.json",
        draftArtifactSha256=_artifact_sha256(draft_wire),
        proposalPath="compiled-proposal.json",
        proposalArtifactSha256=_artifact_sha256(proposal_wire),
        claimStoreId=receipt.claim_store_id,
        claimDigest=receipt.pending_claim.binding.claim_digest,
        gateDContextDigest=receipt.gate_d_context_digest,
        pendingClaimStateDigest=receipt.pending_claim.state_digest,
        cleanupResultDigest=receipt.cleanup_result.cleanup_digest,
        resourceAbsenceDigest=receipt.cleanup_result.resource_absence_digest,
        providerRouteAttestationDigest=(receipt.cleanup_result.provider_route_attestation_digest),
        intendedTerminalDisposition=receipt.intended_terminal_disposition,
    )


def _started_payload(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
) -> dict[str, object]:
    pending_outcome = receipt.pending_claim.pending_outcome
    if pending_outcome is None:  # pragma: no cover - receipt validation requires it
        raise ValueError("compact live terminal receipt pending outcome is absent")
    return {
        "claimStoreId": receipt.claim_store_id,
        "claimDigest": receipt.pending_claim.binding.claim_digest,
        "gateDContextDigest": receipt.gate_d_context_digest,
        "pendingClaimStateDigest": receipt.pending_claim.state_digest,
        "dispatchCount": receipt.pending_claim.dispatch_count,
        "pendingOutcome": pending_outcome.value,
        "cleanupResultDigest": receipt.cleanup_result.cleanup_digest,
        "resourceAbsenceDigest": receipt.cleanup_result.resource_absence_digest,
        "providerRouteAttestationDigest": (
            receipt.cleanup_result.provider_route_attestation_digest
        ),
        "targetRequestAuthority": False,
        "automaticRedispatchAuthority": False,
    }


def _completed_payload(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
    index: CompactSkillBoundWebAnalysisTerminalIndex,
) -> dict[str, object]:
    return {
        "receiptDigest": receipt.receipt_digest,
        "indexDigest": index.index_digest,
        "gateDContextDigest": receipt.gate_d_context_digest,
        "providerRouteAttestationDigest": (
            receipt.cleanup_result.provider_route_attestation_digest
        ),
        "intendedTerminalDisposition": receipt.intended_terminal_disposition.value,
        "cleanupBound": True,
        "terminalJournalCrossLinkRequired": True,
        "targetRequestAuthority": False,
        "automaticRedispatchAuthority": False,
    }


def publish_compact_skill_bound_web_analysis_terminal_run(
    output_root: Path,
    *,
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
    signed_authorization: SignedWebAnalysisOneCallAuthorization,
    draft: SkillBoundWebAnalysisProposalDraft | None,
    proposal: CompiledSkillBoundWebAnalysisProposal | None,
) -> CompactSkillBoundWebAnalysisTerminalPublication:
    """Write and seal the fixed terminal inventory exactly once."""

    try:
        if type(receipt) is not CompactSkillBoundWebAnalysisTerminalReceipt:
            raise TypeError("terminal publication requires the exact receipt type")
        if type(signed_authorization) is not SignedWebAnalysisOneCallAuthorization:
            raise TypeError("terminal publication requires the exact signed authorization type")
        if draft is not None and type(draft) is not SkillBoundWebAnalysisProposalDraft:
            raise TypeError("terminal publication draft type differs")
        if proposal is not None and type(proposal) is not CompiledSkillBoundWebAnalysisProposal:
            raise TypeError("terminal publication proposal type differs")
        canonical_receipt = CompactSkillBoundWebAnalysisTerminalReceipt.model_validate_json(
            receipt.model_dump_json(by_alias=True)
        )
        canonical_authorization = SignedWebAnalysisOneCallAuthorization.model_validate_json(
            signed_authorization.model_dump_json(by_alias=True)
        )
        canonical_draft = (
            None
            if draft is None
            else SkillBoundWebAnalysisProposalDraft.model_validate_json(
                draft.model_dump_json(by_alias=True)
            )
        )
        canonical_proposal = (
            None
            if proposal is None
            else CompiledSkillBoundWebAnalysisProposal.model_validate_json(
                proposal.model_dump_json(by_alias=True)
            )
        )
        if (
            canonical_receipt != receipt
            or canonical_authorization != signed_authorization
            or canonical_authorization != receipt.signed_authorization
            or canonical_draft != receipt.draft
            or canonical_proposal != receipt.compiled_proposal
        ):
            raise ValueError("terminal publication artifacts differ from receipt")
        index = _index_for(receipt, signed_authorization, draft, proposal)
        root = require_compact_skill_bound_web_analysis_terminal_output_root(Path(output_root))
        expected_run_path = compact_skill_bound_web_analysis_terminal_run_path(
            root, receipt.pending_claim
        )
        store = RunStore.create(
            root,
            f"{_CAMPAIGN_PREFIX}-{receipt.pending_claim.binding.claim_digest}",
            run_id=receipt.terminal_run_id,
        )
        if store.path != expected_run_path:
            raise ValueError("terminal publication path differs from its durable claim")
        store.append_event(_STARTED_EVENT, _started_payload(receipt))
        store.write_json(_RECEIPT_PATH, receipt.model_dump(mode="json", by_alias=True))
        store.write_json(
            _AUTHORIZATION_PATH,
            signed_authorization.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            _DRAFT_PATH,
            None if draft is None else draft.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            _PROPOSAL_PATH,
            None if proposal is None else proposal.model_dump(mode="json", by_alias=True),
        )
        store.write_json(_INDEX_PATH, index.model_dump(mode="json", by_alias=True))
        store.append_event(_COMPLETED_EVENT, _completed_payload(receipt, index))
        seal = store.seal()
        verification = load_verified_run_snapshot(
            store.path, expected_run_id=receipt.terminal_run_id
        ).verification
        if (
            verification.root_digest != seal.root_digest
            or verification.seal_count != 1
            or verification.artifact_count != len(_ARTIFACT_PATHS)
            or verification.event_count != 2
        ):
            raise ValueError("sealed terminal publication shape differs")
        return CompactSkillBoundWebAnalysisTerminalPublication(
            run_path=store.path,
            run_id=receipt.terminal_run_id,
            root_digest=seal.root_digest,
        )
    except CompactSkillBoundWebAnalysisTerminalReceiptError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisTerminalReceiptError(
            "compact live terminal publication failed closed"
        ) from exc


def _require_run_anchor(value: str, *, label: str, run_id: bool = False) -> None:
    pattern = _RUN_ID_PATTERN if run_id else _SHA256_PATTERN
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{label} independent anchor is invalid")


def _strict_artifact(
    snapshot: VerifiedRunSnapshot,
    path: str,
    model_type: type[BaseModel],
    *,
    max_bytes: int,
) -> BaseModel:
    raw = snapshot.artifact_bytes(path)
    decoded = parse_strict_json_bytes(
        raw,
        label=f"compact live terminal artifact {path}",
        max_bytes=max_bytes,
        max_depth=64,
        max_nodes=100_000,
    )
    if type(decoded) is not dict:
        raise ValueError(f"compact live terminal artifact {path} must be an object")
    value = model_type.model_validate_json(
        canonical_json_bytes(
            decoded,
            label=f"canonical compact live terminal artifact {path}",
            max_bytes=max_bytes,
        )
    )
    if value.model_dump(mode="json", by_alias=True) != decoded:
        raise ValueError(f"compact live terminal artifact {path} fields differ")
    return value


def _strict_optional_artifact(
    snapshot: VerifiedRunSnapshot,
    path: str,
    model_type: type[BaseModel],
    *,
    max_bytes: int,
) -> BaseModel | None:
    decoded = parse_strict_json_bytes(
        snapshot.artifact_bytes(path),
        label=f"compact live terminal artifact {path}",
        max_bytes=max_bytes,
        max_depth=64,
        max_nodes=100_000,
    )
    if decoded is None:
        return None
    if type(decoded) is not dict:
        raise ValueError(f"compact live terminal artifact {path} must be an object or null")
    value = model_type.model_validate_json(
        canonical_json_bytes(
            decoded,
            label=f"canonical compact live terminal artifact {path}",
            max_bytes=max_bytes,
        )
    )
    if value.model_dump(mode="json", by_alias=True) != decoded:
        raise ValueError(f"compact live terminal artifact {path} fields differ")
    return value


def _require_terminal_claim_cross_link(
    terminal: WebAnalysisLiveClaimJournalEntry,
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
) -> None:
    pending = receipt.pending_claim
    if (
        terminal.phase is not WebAnalysisLiveClaimPhase.TERMINAL
        or terminal.binding != pending.binding
        or terminal.reserved_at != pending.reserved_at
        or terminal.live_started_at != pending.live_started_at
        or terminal.dispatch_started_at != pending.dispatch_started_at
        or terminal.pending_cleanup_at != pending.pending_cleanup_at
        or terminal.pending_outcome is not pending.pending_outcome
        or terminal.dispatch_count != pending.dispatch_count
        or terminal.terminal_disposition is not receipt.intended_terminal_disposition
        or terminal.cleanup_result_digest != receipt.cleanup_result.cleanup_digest
        or terminal.resource_absence_digest != receipt.cleanup_result.resource_absence_digest
        or terminal.terminal_receipt_digest != receipt.receipt_digest
        or terminal.event_digests[:-1] != pending.event_digests
        or len(terminal.event_digests) != len(pending.event_digests) + 1
    ):
        raise ValueError("terminal live claim does not point back to the exact receipt")


def _load_claim_for_publication_phase(
    journal: WebAnalysisLiveClaimJournal,
    *,
    expected_claim_store_id: str,
    expected_claim_digest: str,
    require_terminal: bool,
) -> WebAnalysisLiveClaimJournalEntry:
    if type(require_terminal) is not bool:
        raise TypeError("terminal publication phase selector must be a literal boolean")
    if type(journal) is not WebAnalysisLiveClaimJournal:
        raise TypeError("terminal verification requires the exact live claim journal type")
    if journal.store_id != expected_claim_store_id:
        raise ValueError("live claim journal store identity differs")
    entry = journal.inspect(f"web-analysis-live-claim:{expected_claim_digest}")
    expected_phase = (
        WebAnalysisLiveClaimPhase.TERMINAL
        if require_terminal
        else WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    )
    if entry is None or entry.phase is not expected_phase:
        raise ValueError("expected live claim publication phase is absent")
    return entry


def _load_terminal_publication_anchor(
    journal: WebAnalysisLiveClaimJournal,
    *,
    claim: WebAnalysisLiveClaimJournalEntry,
    mode: _PublicationLoadMode,
    expected_output_root: Path,
    expected_run_path: Path,
    expected_run_id: str,
    expected_root_digest: str | None,
    expected_receipt_digest: str,
    expected_live_attestation_digest: str | None,
) -> WebAnalysisLiveClaimTerminalPublication:
    publication = journal.inspect_terminal_publication(claim.binding.claim_id)
    if (
        publication is None
        or publication.claim_id != claim.binding.claim_id
        or publication.claim_digest != claim.binding.claim_digest
        or publication.output_root != os.path.abspath(expected_output_root)
        or publication.run_path != os.path.abspath(expected_run_path)
        or publication.run_id != expected_run_id
        or publication.receipt_digest != expected_receipt_digest
        or publication.live_attestation_digest != expected_live_attestation_digest
    ):
        raise ValueError("durable terminal publication anchor differs")
    if mode == "candidate":
        if (
            expected_root_digest is not None
            or publication.root_digest is not None
            or publication.publication_digest is not None
            or publication.pending_claim_state_digest != claim.state_digest
        ):
            raise ValueError("durable terminal publication candidate intent differs")
    elif (
        expected_root_digest is None
        or publication.root_digest != expected_root_digest
        or publication.publication_digest is None
    ):
        raise ValueError("durable terminal publication root anchor differs")
    if mode == "terminal":
        if (
            claim.phase is not WebAnalysisLiveClaimPhase.TERMINAL
            or publication.cleanup_result_digest != claim.cleanup_result_digest
            or publication.resource_absence_digest != claim.resource_absence_digest
            or publication.intended_terminal_disposition is not claim.terminal_disposition
            or publication.receipt_digest != claim.terminal_receipt_digest
        ):
            raise ValueError("terminal claim differs from its durable publication anchor")
    elif publication.pending_claim_state_digest != claim.state_digest:
        raise ValueError("pending claim differs from its durable publication intent")
    return publication


def _require_same_terminal_publication(
    before: WebAnalysisLiveClaimTerminalPublication,
    after: WebAnalysisLiveClaimTerminalPublication,
) -> None:
    if after != before:
        raise ValueError("durable terminal publication changed during strict receipt reload")


def _load_gate_d_context(
    journal: WebAnalysisLiveClaimJournal,
    *,
    claim_id: str,
) -> WebAnalysisLiveClaimGateDContext:
    context = journal.inspect_gate_d_context(claim_id)
    if type(context) is not WebAnalysisLiveClaimGateDContext:
        raise ValueError("durable Gate-D context is absent")
    return context


def _authorization_timestamp(value: VerifiedWebAnalysisOneCallAuthorization) -> str:
    return value.evaluated_at.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _claim_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _require_gate_d_context_binding(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
    context: WebAnalysisLiveClaimGateDContext,
) -> None:
    claim = receipt.pending_claim
    initial = receipt.initial_authorization_verification
    before_dispatch = receipt.pre_dispatch_authorization_verification
    transport = receipt.transport_binding
    initial_time = initial.evaluated_at
    reserved_at = _claim_timestamp(claim.reserved_at)
    if initial_time > reserved_at or reserved_at >= initial.expires_at:
        raise ValueError("initial Gate-D authorization follows durable reservation")
    if (
        context.claim_id != claim.binding.claim_id
        or context.claim_digest != claim.binding.claim_digest
        or receipt.gate_d_context_digest != context.context_digest
        or context.initial_authorization_verification_digest != initial.verification_digest
        or context.initial_authorization_evaluated_at != _authorization_timestamp(initial)
        or context.initial_authorization_expires_at
        != initial.expires_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
    ):
        raise ValueError("terminal receipt initial Gate-D context differs")
    if context.pre_dispatch_authorization_verification_digest is None:
        if (
            before_dispatch is not None
            or context.provider_route_attestation_digest is not None
            or receipt.provider_route_attestation is not None
            or receipt.cleanup_result.provider_route_attestation_digest is not None
        ):
            raise ValueError(
                "planned-only transport receipt carries unrecorded pre-dispatch evidence"
            )
        return
    expected_lease_id = _expected_transport_binding_lease_id(transport)
    live_started_at = claim.live_started_at
    upper_bound_at = claim.dispatch_started_at or claim.pending_cleanup_at
    if (
        before_dispatch is None
        or live_started_at is None
        or upper_bound_at is None
        or context.pre_dispatch_authorization_verification_digest
        != before_dispatch.verification_digest
        or context.pre_dispatch_authorization_evaluated_at
        != _authorization_timestamp(before_dispatch)
        or context.pre_dispatch_authorization_expires_at
        != before_dispatch.expires_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
        or context.provider_route_attestation_digest is None
        or context.provider_route_attestation_digest
        != receipt.cleanup_result.provider_route_attestation_digest
        or (
            receipt.provider_route_attestation is not None
            and context.provider_route_attestation_digest
            != receipt.provider_route_attestation.attestation_digest
        )
        or context.transport_execution_id != receipt.transport_execution_id
        or context.lease_ids != (expected_lease_id,)
        or transport.lease_ids != (expected_lease_id,)
        or receipt.cleanup_result.revoked_lease_ids != (expected_lease_id,)
        or context.lease_ids != transport.lease_ids
        or context.worker_context_digest != transport.worker_context_digest
        or context.job_metadata_digest != transport.job_metadata_digest
        or context.transport_binding_digest != transport.binding_digest
        or before_dispatch.evaluated_at <= initial_time
        or before_dispatch.evaluated_at < _claim_timestamp(live_started_at)
        or before_dispatch.evaluated_at > _claim_timestamp(upper_bound_at)
        or (
            claim.dispatch_started_at is not None
            and before_dispatch.expires_at <= _claim_timestamp(claim.dispatch_started_at)
        )
    ):
        raise ValueError("terminal receipt durable pre-dispatch Gate-D context differs")


def _require_provider_route_binding(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
) -> None:
    route = receipt.provider_route_attestation
    if route is None:
        return
    claim = receipt.pending_claim
    live = receipt.live_materialization_attestation
    if (
        live is None
        or route.claim_digest != claim.binding.claim_digest
        or route.resource_owner != claim.binding.resources.resource_owner
        or route.live_materialization_attestation_digest != live.attestation_digest
        or route.runtime_container_name != live.runtime_container_name
        or route.runtime_container_id != live.runtime_container_id
        or route.network_name != live.network_name
        or route.network_id != live.network_id
        or route.provider_registration_digest != receipt.admission.provider_registration_digest
        or route.provider_registration_digest != claim.binding.provider_registration_digest
        or route.provider_endpoint != str(receipt.provider_registration.endpoint)
        or route.attestation_digest != receipt.cleanup_result.provider_route_attestation_digest
    ):
        raise ValueError("terminal receipt Provider route lineage differs")


def _verify_historical_authorizations(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
    signed: SignedWebAnalysisOneCallAuthorization,
    *,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    transport_pin: WebAnalysisTransportRuntimePin,
    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
    expected_trust_anchor_digest: str,
) -> None:
    initial_auth = WebAnalysisOneCallAuthorizationVerifier(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=expected_trust_anchor_digest,
        clock=lambda: receipt.initial_authorization_verification.evaluated_at,
    ).verify(
        signed,
        admission=admission,
        live_request=preparation_run.live_request,
        capacity_pin=capacity_run.pin,
        transport_pin=transport_pin,
    )
    recorded_pre_dispatch = receipt.pre_dispatch_authorization_verification
    pre_dispatch_auth = (
        None
        if recorded_pre_dispatch is None
        else WebAnalysisOneCallAuthorizationVerifier(
            trust_anchor=trust_anchor,
            expected_trust_anchor_digest=expected_trust_anchor_digest,
            clock=lambda: recorded_pre_dispatch.evaluated_at,
        ).verify(
            signed,
            admission=admission,
            live_request=preparation_run.live_request,
            capacity_pin=capacity_run.pin,
            transport_pin=transport_pin,
        )
    )
    if (
        initial_auth != receipt.initial_authorization_verification
        or pre_dispatch_auth != recorded_pre_dispatch
    ):
        raise ValueError("historical one-call authorization verification differs")


def _verify_terminal_proposal(
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt,
    draft: SkillBoundWebAnalysisProposalDraft | None,
    proposal: CompiledSkillBoundWebAnalysisProposal | None,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_transport_pin_digest: str,
) -> CompiledSkillBoundWebAnalysisProposal | None:
    if receipt.intended_terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.SUCCESS:
        if draft is None or proposal is None:
            raise ValueError("terminal success proposal artifacts are absent")
        draft_bytes = canonical_json_bytes(
            draft.model_dump(mode="json", by_alias=True),
            label="compact live terminal draft",
            max_bytes=_MAX_DRAFT_BYTES,
        )
        observation = receipt.dispatch_observation
        if (
            observation.response_evidence_available is not True
            or observation.response_sha256 != sha256(draft_bytes).hexdigest()
            or observation.response_bytes != len(draft_bytes)
        ):
            raise ValueError("terminal success response evidence differs from draft")
        reparsed = parse_skill_bound_web_analysis_proposal_draft(
            draft_bytes, snapshot=skill_run.snapshot
        )
        verified = verify_compiled_skill_bound_web_analysis_proposal(
            proposal,
            source=source,
            skill_run=skill_run,
            draft=reparsed,
            transport_pin=transport_pin,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        if reparsed != draft or verified != proposal:
            raise ValueError("terminal success proposal verification differs")
        return verified
    if draft is not None or proposal is not None:
        raise ValueError("non-success terminal Run contains proposal artifacts")
    return None


def _require_terminal_publication_load_anchors(
    *,
    mode: _PublicationLoadMode,
    expected_run_id: str,
    expected_root_digest: str | None,
    expected_receipt_digest: str,
    expected_claim_digest: str,
    expected_claim_store_id: str,
    expected_trust_anchor_digest: str,
) -> bool:
    if mode not in {"candidate", "anchored-pending", "terminal"}:
        raise ValueError("terminal publication load mode is invalid")
    anchors: tuple[tuple[str, str, bool], ...] = (
        ("terminal Run ID", expected_run_id, True),
        ("terminal receipt", expected_receipt_digest, False),
        ("live claim", expected_claim_digest, False),
        ("claim store", expected_claim_store_id, False),
        ("authorization trust anchor", expected_trust_anchor_digest, False),
    )
    if expected_root_digest is not None:
        anchors = (*anchors, ("terminal Run root", expected_root_digest, False))
    elif mode != "candidate":
        raise ValueError("anchored terminal publication requires a root digest")
    for label, value, run_id in anchors:
        _require_run_anchor(value, label=label, run_id=run_id)
    return mode == "terminal"


def _load_verified_compact_skill_bound_web_analysis_terminal_publication(
    run_path: Path,
    *,
    mode: _PublicationLoadMode,
    expected_output_root: Path,
    expected_run_id: str,
    expected_root_digest: str | None,
    expected_receipt_digest: str,
    expected_claim_digest: str,
    expected_live_attestation_digest: str | None,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    transport_pin: WebAnalysisTransportRuntimePin,
    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
    expected_trust_anchor_digest: str,
    journal: WebAnalysisLiveClaimJournal,
    expected_claim_store_id: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
    expected_preparation_run_id: str,
    expected_preparation_root_digest: str,
    expected_preparation_digest: str,
    expected_preparation_index_digest: str,
    expected_live_request_digest: str,
) -> (
    VerifiedCompactSkillBoundWebAnalysisTerminalRun
    | VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication
):
    """Strictly reload a sealed terminal publication under independent anchors."""

    try:
        require_terminal = _require_terminal_publication_load_anchors(
            mode=mode,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
            expected_receipt_digest=expected_receipt_digest,
            expected_claim_digest=expected_claim_digest,
            expected_claim_store_id=expected_claim_store_id,
            expected_trust_anchor_digest=expected_trust_anchor_digest,
        )
        _require_trusted_terminal_run_path(
            run_path,
            expected_output_root=expected_output_root,
            expected_run_id=expected_run_id,
            expected_claim_digest=expected_claim_digest,
        )
        if expected_live_attestation_digest is not None:
            _require_run_anchor(
                expected_live_attestation_digest,
                label="live materialization attestation",
            )
        before = _load_claim_for_publication_phase(
            journal,
            expected_claim_store_id=expected_claim_store_id,
            expected_claim_digest=expected_claim_digest,
            require_terminal=require_terminal,
        )
        before_gate_d = _load_gate_d_context(
            journal,
            claim_id=before.binding.claim_id,
        )
        before_publication = _load_terminal_publication_anchor(
            journal,
            claim=before,
            mode=mode,
            expected_output_root=expected_output_root,
            expected_run_path=run_path,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
            expected_receipt_digest=expected_receipt_digest,
            expected_live_attestation_digest=expected_live_attestation_digest,
        )

        planned = plan_prepared_compact_skill_bound_web_analysis_admission(
            source=source,
            skill_run=skill_run,
            capacity_run=capacity_run,
            preparation_run=preparation_run,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_capacity_run_id=expected_capacity_run_id,
            expected_capacity_root_digest=expected_capacity_root_digest,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_capacity_proof_digest=expected_capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                expected_capacity_model_materialization_attestation_digest
            ),
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_preparation_run_id=expected_preparation_run_id,
            expected_preparation_root_digest=expected_preparation_root_digest,
            expected_preparation_digest=expected_preparation_digest,
            expected_preparation_index_digest=expected_preparation_index_digest,
            expected_live_request_digest=expected_live_request_digest,
        )
        planned = verify_planned_prepared_compact_skill_bound_web_analysis_admission(
            planned,
            source=source,
            skill_run=skill_run,
            capacity_run=capacity_run,
            preparation_run=preparation_run,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_capacity_run_id=expected_capacity_run_id,
            expected_capacity_root_digest=expected_capacity_root_digest,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_capacity_proof_digest=expected_capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                expected_capacity_model_materialization_attestation_digest
            ),
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_preparation_run_id=expected_preparation_run_id,
            expected_preparation_root_digest=expected_preparation_root_digest,
            expected_preparation_digest=expected_preparation_digest,
            expected_preparation_index_digest=expected_preparation_index_digest,
            expected_live_request_digest=expected_live_request_digest,
        )
        if planned.admission != admission:
            raise ValueError("supplied compact live admission differs from strict replan")
        if (
            type(transport_pin) is not WebAnalysisTransportRuntimePin
            or transport_pin.pin_digest != expected_transport_pin_digest
        ):
            raise ValueError("compact live transport Pin differs from independent anchor")

        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        records = {artifact.path for seal in initial.seals for artifact in seal.artifacts}
        if (
            (
                expected_root_digest is not None
                and initial.verification.root_digest != expected_root_digest
            )
            or initial.verification.seal_count != 1
            or initial.verification.artifact_count != len(_ARTIFACT_PATHS)
            or initial.verification.event_count != 2
            or records != _ARTIFACT_PATHS
            or tuple(event.event_type for event in initial.events)
            != (_STARTED_EVENT, _COMPLETED_EVENT)
        ):
            raise ValueError("compact live terminal sealed layout or events differ")
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests={
                _RECEIPT_PATH: _MAX_RECEIPT_BYTES,
                _INDEX_PATH: _MAX_INDEX_BYTES,
                _AUTHORIZATION_PATH: _MAX_AUTHORIZATION_BYTES,
                _DRAFT_PATH: _MAX_DRAFT_BYTES,
                _PROPOSAL_PATH: _MAX_PROPOSAL_BYTES,
            },
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed compact live terminal Run changed while artifacts were loaded",
        )
        receipt = cast(
            CompactSkillBoundWebAnalysisTerminalReceipt,
            _strict_artifact(
                loaded,
                _RECEIPT_PATH,
                CompactSkillBoundWebAnalysisTerminalReceipt,
                max_bytes=_MAX_RECEIPT_BYTES,
            ),
        )
        index = cast(
            CompactSkillBoundWebAnalysisTerminalIndex,
            _strict_artifact(
                loaded,
                _INDEX_PATH,
                CompactSkillBoundWebAnalysisTerminalIndex,
                max_bytes=_MAX_INDEX_BYTES,
            ),
        )
        signed = cast(
            SignedWebAnalysisOneCallAuthorization,
            _strict_artifact(
                loaded,
                _AUTHORIZATION_PATH,
                SignedWebAnalysisOneCallAuthorization,
                max_bytes=_MAX_AUTHORIZATION_BYTES,
            ),
        )
        draft = cast(
            SkillBoundWebAnalysisProposalDraft | None,
            _strict_optional_artifact(
                loaded,
                _DRAFT_PATH,
                SkillBoundWebAnalysisProposalDraft,
                max_bytes=_MAX_DRAFT_BYTES,
            ),
        )
        proposal = cast(
            CompiledSkillBoundWebAnalysisProposal | None,
            _strict_optional_artifact(
                loaded,
                _PROPOSAL_PATH,
                CompiledSkillBoundWebAnalysisProposal,
                max_bytes=_MAX_PROPOSAL_BYTES,
            ),
        )
        expected_index = _index_for(receipt, signed, draft, proposal)
        raw_artifact_digests = {
            path: sha256(loaded.artifact_bytes(path)).hexdigest()
            for path in (_RECEIPT_PATH, _AUTHORIZATION_PATH, _DRAFT_PATH, _PROPOSAL_PATH)
        }
        if (
            receipt.terminal_run_id != expected_run_id
            or expected_run_id
            != compact_skill_bound_web_analysis_terminal_run_id(receipt.pending_claim)
            or Path(os.path.abspath(run_path))
            != Path(
                os.path.abspath(
                    compact_skill_bound_web_analysis_terminal_run_path(
                        expected_output_root,
                        receipt.pending_claim,
                    )
                )
            )
            or receipt.receipt_digest != expected_receipt_digest
            or receipt.pending_claim.binding.claim_digest != expected_claim_digest
            or (
                None
                if receipt.live_materialization_attestation is None
                else receipt.live_materialization_attestation.attestation_digest
            )
            != expected_live_attestation_digest
            or receipt.admission != admission
            or receipt.capacity_pin != capacity_run.pin
            or receipt.transport_pin != transport_pin
            or receipt.provider_registration != planned.registration
            or receipt.provider_chat_request != planned.chat
            or receipt.claim_store_id != expected_claim_store_id
            or receipt.transport_execution_id
            != f"exec_{receipt.pending_claim.binding.resources.resource_owner}"
            or receipt.transport_binding.live_claim_digest != expected_claim_digest
            or receipt.transport_binding.tool_request.request_id
            != f"tool_{receipt.pending_claim.binding.resources.resource_owner}"
            or receipt.transport_binding.tool_request.agent_id != _LIVE_AGENT_ID
            or receipt.cleanup_result.transport_cleanup.execution_id
            != receipt.transport_execution_id
            or receipt.cleanup_result.transport_cleanup.external_network
            != receipt.pending_claim.binding.resources.network_name
            or receipt.cleanup_result.transport_cleanup.transport_pin_digest
            != expected_transport_pin_digest
            or receipt.cleanup_result.revoked_lease_ids != receipt.transport_binding.lease_ids
            or receipt.cleanup_result.claim_store_id != expected_claim_store_id
            or receipt.cleanup_result.claim_digest != expected_claim_digest
            or receipt.cleanup_result.pending_claim_state_digest
            != receipt.pending_claim.state_digest
            or receipt.cleanup_result.dispatch_observation_digest
            != receipt.dispatch_observation.observation_digest
            or receipt.cleanup_result.live_attestation_digest != expected_live_attestation_digest
            or before_publication.pending_claim_state_digest != receipt.pending_claim.state_digest
            or before_publication.cleanup_result_digest != receipt.cleanup_result.cleanup_digest
            or before_publication.resource_absence_digest
            != receipt.cleanup_result.resource_absence_digest
            or before_publication.intended_terminal_disposition
            is not receipt.intended_terminal_disposition
            or receipt.signed_authorization != signed
            or receipt.draft != draft
            or receipt.compiled_proposal != proposal
            or index != expected_index
            or index.receipt_artifact_sha256 != raw_artifact_digests[_RECEIPT_PATH]
            or index.authorization_artifact_sha256 != raw_artifact_digests[_AUTHORIZATION_PATH]
            or index.draft_artifact_sha256 != raw_artifact_digests[_DRAFT_PATH]
            or index.proposal_artifact_sha256 != raw_artifact_digests[_PROPOSAL_PATH]
            or index.run_id != expected_run_id
            or receipt.intended_terminal_disposition
            is not _terminal_disposition_for(
                receipt.dispatch_observation.pending_outcome,
                response_evidence_available=(
                    receipt.dispatch_observation.response_evidence_available
                ),
            )
        ):
            raise ValueError("compact live terminal artifact lineage differs")

        _require_gate_d_context_binding(receipt, before_gate_d)
        _require_provider_route_binding(receipt)

        _verify_historical_authorizations(
            receipt,
            signed,
            admission=admission,
            preparation_run=preparation_run,
            capacity_run=capacity_run,
            transport_pin=transport_pin,
            trust_anchor=trust_anchor,
            expected_trust_anchor_digest=expected_trust_anchor_digest,
        )
        verified_proposal = _verify_terminal_proposal(
            receipt,
            draft,
            proposal,
            source=source,
            skill_run=skill_run,
            transport_pin=transport_pin,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )

        started, completed = loaded.events
        if started.payload != _started_payload(receipt) or completed.payload != _completed_payload(
            receipt, index
        ):
            raise ValueError("compact live terminal audit event payload differs")
        if require_terminal:
            _require_terminal_claim_cross_link(before, receipt)
        elif before != receipt.pending_claim:
            raise ValueError("pending live claim differs from sealed terminal publication")
        after = journal.inspect(receipt.pending_claim.binding.claim_id)
        if after is None or after != before:
            raise ValueError("live claim changed during strict receipt reload")
        after_gate_d = _load_gate_d_context(
            journal,
            claim_id=receipt.pending_claim.binding.claim_id,
        )
        if after_gate_d != before_gate_d:
            raise ValueError("durable Gate-D context changed during strict receipt reload")
        after_publication = _load_terminal_publication_anchor(
            journal,
            claim=after,
            mode=mode,
            expected_output_root=expected_output_root,
            expected_run_path=run_path,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
            expected_receipt_digest=expected_receipt_digest,
            expected_live_attestation_digest=expected_live_attestation_digest,
        )
        _require_same_terminal_publication(before_publication, after_publication)
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            loaded,
            final,
            message="sealed compact live terminal Run changed after verification",
        )
        verification = final.verification.model_copy(deep=True)
        if require_terminal:
            return VerifiedCompactSkillBoundWebAnalysisTerminalRun(
                run_path=final.run_path,
                verification=verification,
                index=index,
                receipt=receipt,
                signed_authorization=signed,
                gate_d_context=after_gate_d,
                draft=draft,
                proposal=verified_proposal,
                terminal_claim=after,
            )
        attestation = receipt.live_materialization_attestation
        return VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication(
            run_path=final.run_path,
            run_id=verification.run_id,
            root_digest=verification.root_digest,
            verification=verification,
            receipt_digest=receipt.receipt_digest,
            gate_d_context_digest=after_gate_d.context_digest,
            cleanup_result_digest=receipt.cleanup_result.cleanup_digest,
            resource_absence_digest=receipt.cleanup_result.resource_absence_digest,
            live_attestation_digest=(
                None if attestation is None else attestation.attestation_digest
            ),
            provider_route_attestation_digest=(
                receipt.cleanup_result.provider_route_attestation_digest
            ),
            intended_terminal_disposition=receipt.intended_terminal_disposition,
            pending_claim=after,
            verified_candidate=None,
        )
    except CompactSkillBoundWebAnalysisTerminalReceiptError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisTerminalReceiptError(
            "compact live terminal Run failed strict verification"
        ) from exc


def load_verified_compact_skill_bound_web_analysis_terminal_run(
    run_path: Path,
    *,
    expected_output_root: Path,
    expected_run_id: str,
    expected_root_digest: str,
    expected_receipt_digest: str,
    expected_claim_digest: str,
    expected_live_attestation_digest: str | None,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    transport_pin: WebAnalysisTransportRuntimePin,
    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
    expected_trust_anchor_digest: str,
    journal: WebAnalysisLiveClaimJournal,
    expected_claim_store_id: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
    expected_preparation_run_id: str,
    expected_preparation_root_digest: str,
    expected_preparation_digest: str,
    expected_preparation_index_digest: str,
    expected_live_request_digest: str,
) -> VerifiedCompactSkillBoundWebAnalysisTerminalRun:
    """Strictly reload a cleanup-bound terminal Run under independent anchors."""

    result = _load_verified_compact_skill_bound_web_analysis_terminal_publication(
        run_path,
        mode="terminal",
        expected_output_root=expected_output_root,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
        expected_receipt_digest=expected_receipt_digest,
        expected_claim_digest=expected_claim_digest,
        expected_live_attestation_digest=expected_live_attestation_digest,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
        admission=admission,
        transport_pin=transport_pin,
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=expected_trust_anchor_digest,
        journal=journal,
        expected_claim_store_id=expected_claim_store_id,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        expected_skill_run_id=expected_skill_run_id,
        expected_skill_root_digest=expected_skill_root_digest,
        expected_registry_ref=expected_registry_ref,
        expected_policy_digest=expected_policy_digest,
        expected_capacity_run_id=expected_capacity_run_id,
        expected_capacity_root_digest=expected_capacity_root_digest,
        expected_capacity_pin_digest=expected_capacity_pin_digest,
        expected_capacity_proof_digest=expected_capacity_proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            expected_capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_preparation_run_id=expected_preparation_run_id,
        expected_preparation_root_digest=expected_preparation_root_digest,
        expected_preparation_digest=expected_preparation_digest,
        expected_preparation_index_digest=expected_preparation_index_digest,
        expected_live_request_digest=expected_live_request_digest,
    )
    if type(result) is not VerifiedCompactSkillBoundWebAnalysisTerminalRun:
        raise CompactSkillBoundWebAnalysisTerminalReceiptError(
            "terminal loader returned a pending publication"
        )
    return result


def load_verified_compact_skill_bound_web_analysis_pending_terminal_publication(
    run_path: Path,
    *,
    expected_output_root: Path,
    expected_run_id: str,
    expected_root_digest: str,
    expected_receipt_digest: str,
    expected_claim_digest: str,
    expected_live_attestation_digest: str | None,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    transport_pin: WebAnalysisTransportRuntimePin,
    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
    expected_trust_anchor_digest: str,
    journal: WebAnalysisLiveClaimJournal,
    expected_claim_store_id: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
    expected_preparation_run_id: str,
    expected_preparation_root_digest: str,
    expected_preparation_digest: str,
    expected_preparation_index_digest: str,
    expected_live_request_digest: str,
) -> VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
    """Reload one existing seal for finalize-only crash recovery."""

    result = _load_verified_compact_skill_bound_web_analysis_terminal_publication(
        run_path,
        mode="anchored-pending",
        expected_output_root=expected_output_root,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
        expected_receipt_digest=expected_receipt_digest,
        expected_claim_digest=expected_claim_digest,
        expected_live_attestation_digest=expected_live_attestation_digest,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
        admission=admission,
        transport_pin=transport_pin,
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=expected_trust_anchor_digest,
        journal=journal,
        expected_claim_store_id=expected_claim_store_id,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        expected_skill_run_id=expected_skill_run_id,
        expected_skill_root_digest=expected_skill_root_digest,
        expected_registry_ref=expected_registry_ref,
        expected_policy_digest=expected_policy_digest,
        expected_capacity_run_id=expected_capacity_run_id,
        expected_capacity_root_digest=expected_capacity_root_digest,
        expected_capacity_pin_digest=expected_capacity_pin_digest,
        expected_capacity_proof_digest=expected_capacity_proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            expected_capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_preparation_run_id=expected_preparation_run_id,
        expected_preparation_root_digest=expected_preparation_root_digest,
        expected_preparation_digest=expected_preparation_digest,
        expected_preparation_index_digest=expected_preparation_index_digest,
        expected_live_request_digest=expected_live_request_digest,
    )
    if type(result) is not VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
        raise CompactSkillBoundWebAnalysisTerminalReceiptError(
            "pending loader returned a terminal publication"
        )
    return result


def load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate(
    run_path: Path,
    *,
    expected_output_root: Path,
    expected_run_id: str,
    expected_receipt_digest: str,
    expected_claim_digest: str,
    expected_live_attestation_digest: str | None,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    transport_pin: WebAnalysisTransportRuntimePin,
    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
    expected_trust_anchor_digest: str,
    journal: WebAnalysisLiveClaimJournal,
    expected_claim_store_id: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
    expected_preparation_run_id: str,
    expected_preparation_root_digest: str,
    expected_preparation_digest: str,
    expected_preparation_index_digest: str,
    expected_live_request_digest: str,
) -> VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
    """Strict-load an unanchored intent's exact Run before its root CAS.

    The returned ``verified_candidate`` is the only value accepted by the
    journal anchor boundary.  This loader requires the publication row to stay
    unanchored and unchanged across all artifact and lineage verification.
    """

    result = _load_verified_compact_skill_bound_web_analysis_terminal_publication(
        run_path,
        mode="candidate",
        expected_output_root=expected_output_root,
        expected_run_id=expected_run_id,
        expected_root_digest=None,
        expected_receipt_digest=expected_receipt_digest,
        expected_claim_digest=expected_claim_digest,
        expected_live_attestation_digest=expected_live_attestation_digest,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
        admission=admission,
        transport_pin=transport_pin,
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=expected_trust_anchor_digest,
        journal=journal,
        expected_claim_store_id=expected_claim_store_id,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        expected_skill_run_id=expected_skill_run_id,
        expected_skill_root_digest=expected_skill_root_digest,
        expected_registry_ref=expected_registry_ref,
        expected_policy_digest=expected_policy_digest,
        expected_capacity_run_id=expected_capacity_run_id,
        expected_capacity_root_digest=expected_capacity_root_digest,
        expected_capacity_pin_digest=expected_capacity_pin_digest,
        expected_capacity_proof_digest=expected_capacity_proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            expected_capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_preparation_run_id=expected_preparation_run_id,
        expected_preparation_root_digest=expected_preparation_root_digest,
        expected_preparation_digest=expected_preparation_digest,
        expected_preparation_index_digest=expected_preparation_index_digest,
        expected_live_request_digest=expected_live_request_digest,
    )
    if type(result) is not VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
        raise CompactSkillBoundWebAnalysisTerminalReceiptError(
            "candidate loader returned a terminal publication"
        )
    publication = journal.inspect_terminal_publication(result.pending_claim.binding.claim_id)
    if (
        publication is None
        or publication.claim_id != result.pending_claim.binding.claim_id
        or publication.claim_digest != expected_claim_digest
        or publication.pending_claim_state_digest != result.pending_claim.state_digest
        or publication.output_root != os.path.abspath(expected_output_root)
        or publication.run_path != os.path.abspath(run_path)
        or publication.run_id != expected_run_id
        or publication.receipt_digest != expected_receipt_digest
        or publication.live_attestation_digest != expected_live_attestation_digest
        or publication.root_digest is not None
        or publication.publication_digest is not None
    ):
        raise CompactSkillBoundWebAnalysisTerminalReceiptError(
            "candidate loader durable publication intent changed after verification"
        )
    candidate = object.__new__(VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate)
    with _TERMINAL_PUBLICATION_CANDIDATE_LOCK:
        _VERIFIED_TERMINAL_PUBLICATION_CANDIDATES[candidate] = (
            _VerifiedTerminalPublicationCandidateState(
                journal=journal,
                claim_id=publication.claim_id,
                intent_digest=publication.intent_digest,
                root_digest=result.root_digest,
            )
        )
    return replace(result, verified_candidate=candidate)


__all__ = [
    "COMPACT_LIVE_TERMINAL_INDEX_API_VERSION",
    "COMPACT_LIVE_TERMINAL_RECEIPT_API_VERSION",
    "CompactSkillBoundWebAnalysisCleanupResult",
    "CompactSkillBoundWebAnalysisDispatchObservation",
    "CompactSkillBoundWebAnalysisTerminalIndex",
    "CompactSkillBoundWebAnalysisTerminalPublication",
    "CompactSkillBoundWebAnalysisTerminalReceipt",
    "CompactSkillBoundWebAnalysisTerminalReceiptError",
    "CompactSkillBoundWebAnalysisTransportBinding",
    "VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication",
    "VerifiedCompactSkillBoundWebAnalysisTerminalRun",
    "compact_skill_bound_web_analysis_lease_id",
    "compact_skill_bound_web_analysis_terminal_run_id",
    "compact_skill_bound_web_analysis_terminal_run_path",
    "load_verified_compact_skill_bound_web_analysis_pending_terminal_publication",
    "load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate",
    "load_verified_compact_skill_bound_web_analysis_terminal_run",
    "publish_compact_skill_bound_web_analysis_terminal_run",
    "require_compact_skill_bound_web_analysis_terminal_output_root",
]
