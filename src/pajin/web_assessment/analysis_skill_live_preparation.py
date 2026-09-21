"""Zero-dispatch live-call preparation for compact Skill-bound Web analysis.

This module binds an exact, independently reloaded Capacity v2 proof to the
code-owned compact request and local Provider registration metadata.  It does
not resolve credentials, start a model runtime, invoke a model, dispatch a
Provider request, contact a target, or create any downstream authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Final, Literal, Self, cast

from pydantic import AnyHttpUrl, ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.runtime.pinned_workspace import PinnedOutputRoot, active_pinned_workspace_identity
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
    load_verified_web_analysis_capacity_v2_run,
)
from pajin.web_assessment.analysis_local import (
    WEB_ANALYSIS_LOCAL_DURATION_SECONDS,
    WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
    WEB_ANALYSIS_LOCAL_PROVIDER_ID,
    WEB_ANALYSIS_LOCAL_SECRET_REF,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
)

COMPACT_LIVE_REQUEST_API_VERSION: Final = (
    "pajin.dev/compact-skill-bound-web-analysis-live-request/v1alpha1"
)
COMPACT_LIVE_PREPARATION_API_VERSION: Final = (
    "pajin.dev/compact-skill-bound-web-analysis-live-preparation/v1alpha1"
)
COMPACT_LIVE_PREPARATION_INDEX_API_VERSION: Final = (
    "pajin.dev/compact-skill-bound-web-analysis-live-preparation-index/v1alpha1"
)
VERIFIED_COMPACT_LIVE_PREPARATION_API_VERSION: Final = (
    "pajin.dev/verified-compact-skill-bound-web-analysis-live-preparation/v1alpha1"
)
COMPACT_LIVE_PREPARATION_STATUS: Final = "prepared-not-authorized-no-dispatch"

_REQUEST_PATH = "compact-live-request.json"
_PREPARATION_PATH = "compact-live-preparation.json"
_INDEX_PATH = "compact-live-preparation-index.json"
_ARTIFACT_LIMITS: Final = {
    _REQUEST_PATH: 2 * 1024 * 1024,
    _PREPARATION_PATH: 256 * 1024,
    _INDEX_PATH: 256 * 1024,
}
_EXPECTED_ARTIFACTS = frozenset(_ARTIFACT_LIMITS)
_STARTED_EVENT = "web-analysis.compact-live-preparation.started"
_COMPLETED_EVENT = "web-analysis.compact-live-preparation.completed"
_CAMPAIGN_NAME = "compact-live-preparation"
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_RUN_ID_RE = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class CompactSkillBoundWebAnalysisLivePreparationError(ValueError):
    """Raised when a zero-dispatch preparation differs from code authority."""


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Compact live preparation markers must be literal false")
    return False


def _literal_zero(value: object) -> Literal[0]:
    if type(value) is not int or value != 0:
        raise ValueError("Compact live preparation counts must be literal integer zero")
    return 0


def _digest(domain: str, value: object) -> str:
    encoded_domain = domain.encode("ascii", errors="strict")
    payload = canonical_json_bytes(
        value,
        label="compact live preparation identity material",
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    return sha256(
        b"PAJIN-COMPACT-LIVE-PREPARATION\0"
        + len(encoded_domain).to_bytes(4, "big")
        + encoded_domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _artifact_wire(value: object) -> bytes:
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


class _FrozenPreparationModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class CompactSkillBoundWebAnalysisZeroDispatchState(_FrozenPreparationModel):
    """Literal proof that preparation minted no runtime or downstream authority."""

    model_runtime_started: Literal[False] = Field(alias="modelRuntimeStarted")
    model_runtime_start_count: Literal[0] = Field(alias="modelRuntimeStartCount")
    model_invocation_performed: Literal[False] = Field(alias="modelInvocationPerformed")
    model_invocation_count: Literal[0] = Field(alias="modelInvocationCount")
    provider_dispatch_performed: Literal[False] = Field(alias="providerDispatchPerformed")
    provider_dispatch_count: Literal[0] = Field(alias="providerDispatchCount")
    target_request_performed: Literal[False] = Field(alias="targetRequestPerformed")
    target_request_count: Literal[0] = Field(alias="targetRequestCount")
    tool_request_performed: Literal[False] = Field(alias="toolRequestPerformed")
    tool_request_count: Literal[0] = Field(alias="toolRequestCount")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    capability_grant_count: Literal[0] = Field(alias="capabilityGrantCount")
    action_permit_issued: Literal[False] = Field(alias="actionPermitIssued")
    action_permit_count: Literal[0] = Field(alias="actionPermitCount")
    execution_performed: Literal[False] = Field(alias="executionPerformed")
    execution_count: Literal[0] = Field(alias="executionCount")
    finding_created: Literal[False] = Field(alias="findingCreated")
    finding_count: Literal[0] = Field(alias="findingCount")
    graph_admitted: Literal[False] = Field(alias="graphAdmitted")
    graph_admission_count: Literal[0] = Field(alias="graphAdmissionCount")
    report_created: Literal[False] = Field(alias="reportCreated")
    report_count: Literal[0] = Field(alias="reportCount")
    external_delivery_performed: Literal[False] = Field(alias="externalDeliveryPerformed")
    delivery_count: Literal[0] = Field(alias="deliveryCount")
    credential_lease_materialized: Literal[False] = Field(alias="credentialLeaseMaterialized")
    future_live_call_authorized: Literal[False] = Field(alias="futureLiveCallAuthorized")
    provider_dispatch_authority: Literal[False] = Field(alias="providerDispatchAuthority")
    target_request_authority: Literal[False] = Field(alias="targetRequestAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    report_authority: Literal[False] = Field(alias="reportAuthority")
    delivery_authority: Literal[False] = Field(alias="deliveryAuthority")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    automatic_redispatch_authority: Literal[False] = Field(alias="automaticRedispatchAuthority")

    @field_validator(
        "model_runtime_started",
        "model_invocation_performed",
        "provider_dispatch_performed",
        "target_request_performed",
        "tool_request_performed",
        "capability_granted",
        "action_permit_issued",
        "execution_performed",
        "finding_created",
        "graph_admitted",
        "report_created",
        "external_delivery_performed",
        "credential_lease_materialized",
        "future_live_call_authorized",
        "provider_dispatch_authority",
        "target_request_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        "finding_authority",
        "graph_admission_authority",
        "report_authority",
        "delivery_authority",
        "scope_expansion_authority",
        "automatic_redispatch_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator(
        "model_runtime_start_count",
        "model_invocation_count",
        "provider_dispatch_count",
        "target_request_count",
        "tool_request_count",
        "capability_grant_count",
        "action_permit_count",
        "execution_count",
        "finding_count",
        "graph_admission_count",
        "report_count",
        "delivery_count",
        mode="before",
    )
    @classmethod
    def require_zero_counts(cls, value: object) -> Literal[0]:
        return _literal_zero(value)


class CompactSkillBoundWebAnalysisLiveRequest(_FrozenPreparationModel):
    """Exact compact Provider request metadata, still carrying no dispatch authority."""

    api_version: Literal["pajin.dev/compact-skill-bound-web-analysis-live-request/v1alpha1"] = (
        Field(alias="apiVersion")
    )
    kind: Literal["CompactSkillBoundWebAnalysisLiveRequest"]
    request_digest: str = Field(alias="requestDigest", max_length=64)
    status: Literal["prepared-not-authorized-no-dispatch"]
    skill_run_id: str = Field(alias="skillRunId", max_length=64)
    skill_run_root_digest: _Sha256 = Field(alias="skillRunRootDigest")
    skill_snapshot_digest: _Sha256 = Field(alias="skillSnapshotDigest")
    compact_projection_digest: _Sha256 = Field(alias="compactProjectionDigest")
    capacity_compact_projection_digest: _Sha256 = Field(alias="capacityCompactProjectionDigest")
    provider_registration: ProviderRegistration = Field(alias="providerRegistration")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    chat_request: ProviderChatRequest = Field(alias="chatRequest")
    chat_request_digest: _Sha256 = Field(alias="chatRequestDigest")
    capacity_chat_request_digest: _Sha256 = Field(alias="capacityChatRequestDigest")
    execution_state: CompactSkillBoundWebAnalysisZeroDispatchState = Field(alias="executionState")

    @model_validator(mode="after")
    def bind_request(self) -> Self:
        registration = _canonical_registration(self.provider_registration)
        expected_registration = _local_provider_registration(registration.model)
        request = _canonical_chat_request(self.chat_request)
        registration_digest = _digest(
            "provider-registration/v1",
            registration.model_dump(mode="json", by_alias=True),
        )
        request_digest = _digest(
            "provider-chat-request/v1",
            request.model_dump(mode="json", by_alias=True),
        )
        if self.provider_registration != registration or registration != expected_registration:
            raise ValueError("Compact live Provider registration differs from code authority")
        if self.chat_request != request:
            raise ValueError("Compact live Provider request is not canonical")
        if self.provider_registration_digest != registration_digest:
            raise ValueError("Compact live Provider registration digest differs")
        if self.chat_request_digest != request_digest:
            raise ValueError("Compact live Provider request digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"request_digest"},
        )
        digest = _digest("live-request/v1", material)
        if self.request_digest and self.request_digest != digest:
            raise ValueError("Compact live request artifact digest differs")
        object.__setattr__(self, "request_digest", digest)
        return self


class CompactSkillBoundWebAnalysisPreparation(_FrozenPreparationModel):
    """Proof-bound preparation that intentionally stops before authorization."""

    api_version: Literal["pajin.dev/compact-skill-bound-web-analysis-live-preparation/v1alpha1"] = (
        Field(alias="apiVersion")
    )
    kind: Literal["CompactSkillBoundWebAnalysisPreparation"]
    preparation_digest: str = Field(alias="preparationDigest", max_length=64)
    status: Literal["prepared-not-authorized-no-dispatch"]
    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")
    skill_run_id: str = Field(alias="skillRunId", max_length=64)
    skill_run_root_digest: _Sha256 = Field(alias="skillRunRootDigest")
    skill_snapshot_digest: _Sha256 = Field(alias="skillSnapshotDigest")
    capacity_run_id: str = Field(alias="capacityRunId", max_length=64)
    capacity_run_root_digest: _Sha256 = Field(alias="capacityRunRootDigest")
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    capacity_proof_digest: _Sha256 = Field(alias="capacityProofDigest")
    model_materialization_attestation_digest: _Sha256 = Field(
        alias="modelMaterializationAttestationDigest"
    )
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    capacity_compact_projection_digest: _Sha256 = Field(alias="capacityCompactProjectionDigest")
    capacity_chat_request_digest: _Sha256 = Field(alias="capacityChatRequestDigest")
    execution_state: CompactSkillBoundWebAnalysisZeroDispatchState = Field(alias="executionState")

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        if _RUN_ID_RE.fullmatch(self.skill_run_id) is None:
            raise ValueError("Compact live preparation Skill Run ID is invalid")
        if _RUN_ID_RE.fullmatch(self.capacity_run_id) is None:
            raise ValueError("Compact live preparation Capacity Run ID is invalid")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_digest"},
        )
        digest = _digest("live-preparation/v1", material)
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Compact live preparation digest differs")
        object.__setattr__(self, "preparation_digest", digest)
        return self


class CompactSkillBoundWebAnalysisPreparationIndex(_FrozenPreparationModel):
    """Exact three-artifact Run index and duplicate zero-dispatch accounting."""

    api_version: Literal[
        "pajin.dev/compact-skill-bound-web-analysis-live-preparation-index/v1alpha1"
    ] = Field(alias="apiVersion")
    kind: Literal["CompactSkillBoundWebAnalysisPreparationIndex"]
    index_digest: str = Field(alias="indexDigest", max_length=64)
    run_id: str = Field(alias="runId", max_length=64)
    request_path: Literal["compact-live-request.json"] = Field(alias="requestPath")
    request_digest: _Sha256 = Field(alias="requestDigest")
    preparation_path: Literal["compact-live-preparation.json"] = Field(alias="preparationPath")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    status: Literal["prepared-not-authorized-no-dispatch"]
    capacity_run_id: str = Field(alias="capacityRunId", max_length=64)
    capacity_run_root_digest: _Sha256 = Field(alias="capacityRunRootDigest")
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    capacity_proof_digest: _Sha256 = Field(alias="capacityProofDigest")
    model_materialization_attestation_digest: _Sha256 = Field(
        alias="modelMaterializationAttestationDigest"
    )
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    execution_state: CompactSkillBoundWebAnalysisZeroDispatchState = Field(alias="executionState")

    @model_validator(mode="after")
    def bind_index(self) -> Self:
        if _RUN_ID_RE.fullmatch(self.run_id) is None:
            raise ValueError("Compact live preparation Index Run ID is invalid")
        if _RUN_ID_RE.fullmatch(self.capacity_run_id) is None:
            raise ValueError("Compact live preparation Index Capacity Run ID is invalid")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"index_digest"},
        )
        digest = _digest("live-preparation-index/v1", material)
        if self.index_digest and self.index_digest != digest:
            raise ValueError("Compact live preparation Index digest differs")
        object.__setattr__(self, "index_digest", digest)
        return self


class PlannedCompactSkillBoundWebAnalysisCall(_FrozenPreparationModel):
    """In-memory deterministic plan; it remains inert and non-authoritative."""

    live_request: CompactSkillBoundWebAnalysisLiveRequest = Field(alias="liveRequest")
    preparation: CompactSkillBoundWebAnalysisPreparation

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        if (
            self.preparation.live_request_digest != self.live_request.request_digest
            or self.preparation.skill_run_id != self.live_request.skill_run_id
            or self.preparation.skill_run_root_digest != self.live_request.skill_run_root_digest
            or self.preparation.skill_snapshot_digest != self.live_request.skill_snapshot_digest
            or self.preparation.capacity_compact_projection_digest
            != self.live_request.capacity_compact_projection_digest
            or self.preparation.capacity_chat_request_digest
            != self.live_request.capacity_chat_request_digest
            or self.preparation.execution_state != self.live_request.execution_state
        ):
            raise ValueError("Compact live call plan lineage differs")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedCompactSkillBoundWebAnalysisPreparationRun:
    """Strictly reloaded zero-dispatch preparation under independent anchors."""

    run_id: str
    run_path: Path
    root_digest: str
    live_request: CompactSkillBoundWebAnalysisLiveRequest
    preparation: CompactSkillBoundWebAnalysisPreparation
    index: CompactSkillBoundWebAnalysisPreparationIndex
    started_event_hash: str
    completed_event_hash: str


def _zero_dispatch_state() -> CompactSkillBoundWebAnalysisZeroDispatchState:
    return CompactSkillBoundWebAnalysisZeroDispatchState.model_validate(
        {
            "modelRuntimeStarted": False,
            "modelRuntimeStartCount": 0,
            "modelInvocationPerformed": False,
            "modelInvocationCount": 0,
            "providerDispatchPerformed": False,
            "providerDispatchCount": 0,
            "targetRequestPerformed": False,
            "targetRequestCount": 0,
            "toolRequestPerformed": False,
            "toolRequestCount": 0,
            "capabilityGranted": False,
            "capabilityGrantCount": 0,
            "actionPermitIssued": False,
            "actionPermitCount": 0,
            "executionPerformed": False,
            "executionCount": 0,
            "findingCreated": False,
            "findingCount": 0,
            "graphAdmitted": False,
            "graphAdmissionCount": 0,
            "reportCreated": False,
            "reportCount": 0,
            "externalDeliveryPerformed": False,
            "deliveryCount": 0,
            "credentialLeaseMaterialized": False,
            "futureLiveCallAuthorized": False,
            "providerDispatchAuthority": False,
            "targetRequestAuthority": False,
            "toolRequestAuthority": False,
            "capabilityAuthority": False,
            "permitAuthority": False,
            "executionAuthority": False,
            "findingAuthority": False,
            "graphAdmissionAuthority": False,
            "reportAuthority": False,
            "deliveryAuthority": False,
            "scopeExpansionAuthority": False,
            "automaticRedispatchAuthority": False,
        }
    )


def _canonical_registration(registration: ProviderRegistration) -> ProviderRegistration:
    return ProviderRegistration.model_validate(registration.model_dump(mode="python"))


def _canonical_chat_request(request: ProviderChatRequest) -> ProviderChatRequest:
    return ProviderChatRequest.model_validate(request.model_dump(mode="python", by_alias=True))


def _local_provider_registration(model_id: str) -> ProviderRegistration:
    return ProviderRegistration(
        provider_id=WEB_ANALYSIS_LOCAL_PROVIDER_ID,
        endpoint=AnyHttpUrl(WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT),
        model=model_id,
        secret_ref=WEB_ANALYSIS_LOCAL_SECRET_REF,
        allow_streaming=False,
        allowed_function_tools=set(),
        lease_ttl_seconds=WEB_ANALYSIS_LOCAL_DURATION_SECONDS,
        allow_private_networks=True,
        input_cost_per_million_usd=0,
        output_cost_per_million_usd=0,
    )


def _require_anchor(value: str, *, label: str, run_id: bool = False) -> None:
    pattern = _RUN_ID_RE if run_id else _SHA256_RE
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{label} independent anchor is invalid")


def _strict_reload_capacity(
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
) -> VerifiedWebAnalysisCapacityV2Run:
    if type(skill_run) is not VerifiedWebAnalysisSkillProjectionRun:
        raise TypeError("Compact live preparation requires the exact verified Skill type")
    if type(capacity_run) is not VerifiedWebAnalysisCapacityV2Run:
        raise TypeError("Compact live preparation requires the exact verified Capacity type")
    reloaded = load_verified_web_analysis_capacity_v2_run(
        capacity_run.run_path,
        skill_run=skill_run,
        expected_run_id=expected_capacity_run_id,
        expected_root_digest=expected_capacity_root_digest,
        expected_pin_digest=expected_capacity_pin_digest,
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_proof_digest=expected_capacity_proof_digest,
        expected_model_materialization_attestation_digest=(
            expected_capacity_model_materialization_attestation_digest
        ),
    )
    if reloaded != capacity_run:
        raise ValueError("Supplied Capacity v2 object differs from strict reload")
    return reloaded


def plan_compact_skill_bound_web_analysis_call(
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
) -> PlannedCompactSkillBoundWebAnalysisCall:
    """Re-derive one exact inert request after strict Capacity v2 reload."""

    try:
        _require_anchor(expected_skill_run_id, label="Skill Run ID", run_id=True)
        _require_anchor(expected_skill_root_digest, label="Skill Run root")
        _require_anchor(expected_capacity_run_id, label="Capacity Run ID", run_id=True)
        _require_anchor(expected_capacity_root_digest, label="Capacity Run root")
        _require_anchor(expected_capacity_pin_digest, label="Capacity Pin")
        _require_anchor(expected_capacity_proof_digest, label="Capacity Proof")
        _require_anchor(
            expected_capacity_model_materialization_attestation_digest,
            label="Capacity model materialization attestation",
        )
        _require_anchor(expected_transport_pin_digest, label="transport Pin")
        if (
            skill_run.verification.run_id != expected_skill_run_id
            or skill_run.verification.root_digest != expected_skill_root_digest
        ):
            raise ValueError("Verified Skill Run differs from independent anchors")
        capacity = _strict_reload_capacity(
            skill_run=skill_run,
            capacity_run=capacity_run,
            expected_capacity_run_id=expected_capacity_run_id,
            expected_capacity_root_digest=expected_capacity_root_digest,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_capacity_proof_digest=expected_capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                expected_capacity_model_materialization_attestation_digest
            ),
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
        chat_request = _canonical_chat_request(
            build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
        )
        registration = _local_provider_registration(capacity.pin.model_id)
        registration_digest = _digest(
            "provider-registration/v1",
            registration.model_dump(mode="json", by_alias=True),
        )
        chat_request_digest = _digest(
            "provider-chat-request/v1",
            chat_request.model_dump(mode="json", by_alias=True),
        )
        attestation_digest = capacity.evidence.model_materialization_attestation.attestation_digest
        if (
            capacity.run_id != expected_capacity_run_id
            or capacity.root_digest != expected_capacity_root_digest
            or capacity.pin.pin_digest != expected_capacity_pin_digest
            or capacity.proof.proof_digest != expected_capacity_proof_digest
            or capacity.model_materialization_attestation_digest != attestation_digest
            or attestation_digest != expected_capacity_model_materialization_attestation_digest
            or capacity.proof.model_materialization_attestation_digest != attestation_digest
            or capacity.index.model_materialization_attestation_digest != attestation_digest
            or capacity.pin.transport_pin_digest != expected_transport_pin_digest
            or capacity.pin.skill_run_id != expected_skill_run_id
            or capacity.pin.skill_run_root_digest != expected_skill_root_digest
            or capacity.pin.skill_projection_digest != skill_run.snapshot.snapshot_digest
            or capacity.proof.pin_digest != capacity.pin.pin_digest
            or capacity.proof.request_digest != capacity.pin.chat_request_digest
            or capacity.index.pin_digest != capacity.pin.pin_digest
            or capacity.index.proof_digest != capacity.proof.proof_digest
        ):
            raise ValueError("Capacity v2 proof lineage differs from live preparation")
        state = _zero_dispatch_state()
        live_request = CompactSkillBoundWebAnalysisLiveRequest.model_validate(
            {
                "apiVersion": COMPACT_LIVE_REQUEST_API_VERSION,
                "kind": "CompactSkillBoundWebAnalysisLiveRequest",
                "requestDigest": "",
                "status": COMPACT_LIVE_PREPARATION_STATUS,
                "skillRunId": expected_skill_run_id,
                "skillRunRootDigest": expected_skill_root_digest,
                "skillSnapshotDigest": skill_run.snapshot.snapshot_digest,
                "compactProjectionDigest": projection.projection_digest,
                "capacityCompactProjectionDigest": capacity.pin.compact_projection_digest,
                "providerRegistration": registration,
                "providerRegistrationDigest": registration_digest,
                "chatRequest": chat_request,
                "chatRequestDigest": chat_request_digest,
                "capacityChatRequestDigest": capacity.pin.chat_request_digest,
                "executionState": state,
            }
        )
        preparation = CompactSkillBoundWebAnalysisPreparation.model_validate(
            {
                "apiVersion": COMPACT_LIVE_PREPARATION_API_VERSION,
                "kind": "CompactSkillBoundWebAnalysisPreparation",
                "preparationDigest": "",
                "status": COMPACT_LIVE_PREPARATION_STATUS,
                "liveRequestDigest": live_request.request_digest,
                "skillRunId": expected_skill_run_id,
                "skillRunRootDigest": expected_skill_root_digest,
                "skillSnapshotDigest": skill_run.snapshot.snapshot_digest,
                "capacityRunId": expected_capacity_run_id,
                "capacityRunRootDigest": expected_capacity_root_digest,
                "capacityPinDigest": expected_capacity_pin_digest,
                "capacityProofDigest": expected_capacity_proof_digest,
                "modelMaterializationAttestationDigest": (
                    expected_capacity_model_materialization_attestation_digest
                ),
                "transportPinDigest": expected_transport_pin_digest,
                "capacityCompactProjectionDigest": capacity.pin.compact_projection_digest,
                "capacityChatRequestDigest": capacity.pin.chat_request_digest,
                "executionState": state,
            }
        )
        return PlannedCompactSkillBoundWebAnalysisCall(
            liveRequest=live_request,
            preparation=preparation,
        )
    except CompactSkillBoundWebAnalysisLivePreparationError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisLivePreparationError(
            "Compact Skill-bound Web analysis live call planning failed closed"
        ) from exc


def _index_for(
    run_id: str,
    plan: PlannedCompactSkillBoundWebAnalysisCall,
) -> CompactSkillBoundWebAnalysisPreparationIndex:
    preparation = plan.preparation
    return CompactSkillBoundWebAnalysisPreparationIndex.model_validate(
        {
            "apiVersion": COMPACT_LIVE_PREPARATION_INDEX_API_VERSION,
            "kind": "CompactSkillBoundWebAnalysisPreparationIndex",
            "indexDigest": "",
            "runId": run_id,
            "requestPath": _REQUEST_PATH,
            "requestDigest": plan.live_request.request_digest,
            "preparationPath": _PREPARATION_PATH,
            "preparationDigest": preparation.preparation_digest,
            "status": COMPACT_LIVE_PREPARATION_STATUS,
            "capacityRunId": preparation.capacity_run_id,
            "capacityRunRootDigest": preparation.capacity_run_root_digest,
            "capacityPinDigest": preparation.capacity_pin_digest,
            "capacityProofDigest": preparation.capacity_proof_digest,
            "modelMaterializationAttestationDigest": (
                preparation.model_materialization_attestation_digest
            ),
            "transportPinDigest": preparation.transport_pin_digest,
            "executionState": preparation.execution_state,
        }
    )


def _started_payload(plan: PlannedCompactSkillBoundWebAnalysisCall) -> dict[str, object]:
    preparation = plan.preparation
    return {
        "status": COMPACT_LIVE_PREPARATION_STATUS,
        "liveRequestDigest": plan.live_request.request_digest,
        "preparationDigest": preparation.preparation_digest,
        "capacityRunId": preparation.capacity_run_id,
        "capacityRunRootDigest": preparation.capacity_run_root_digest,
        "capacityPinDigest": preparation.capacity_pin_digest,
        "capacityProofDigest": preparation.capacity_proof_digest,
        "modelMaterializationAttestationDigest": (
            preparation.model_materialization_attestation_digest
        ),
        "transportPinDigest": preparation.transport_pin_digest,
        "executionState": preparation.execution_state.model_dump(mode="json", by_alias=True),
    }


def _completed_payload(
    plan: PlannedCompactSkillBoundWebAnalysisCall,
    index: CompactSkillBoundWebAnalysisPreparationIndex,
) -> dict[str, object]:
    return {
        "status": COMPACT_LIVE_PREPARATION_STATUS,
        "liveRequestDigest": plan.live_request.request_digest,
        "preparationDigest": plan.preparation.preparation_digest,
        "indexDigest": index.index_digest,
        "modelRuntimeStartCount": 0,
        "modelInvocationCount": 0,
        "providerDispatchCount": 0,
        "targetRequestCount": 0,
        "toolRequestCount": 0,
        "actionPermitCount": 0,
        "findingCount": 0,
        "graphAdmissionCount": 0,
        "reportCount": 0,
        "deliveryCount": 0,
        "futureLiveCallAuthorized": False,
    }


def _require_disjoint_preparation_output(
    output_root: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
) -> None:
    if not isinstance(output_root, Path):
        raise TypeError("Compact live preparation output root must be a Path")
    if ".." in output_root.parts:
        raise ValueError("Compact live preparation output root cannot contain parent traversal")
    output = output_root.expanduser().resolve(strict=False)
    inputs = (
        skill_run.run_path.expanduser().resolve(strict=True),
        capacity_run.run_path.expanduser().resolve(strict=True),
    )
    if any(
        output == value or value in output.parents or output in value.parents for value in inputs
    ):
        raise ValueError("Compact live preparation output must be disjoint from immutable Runs")


def create_compact_skill_bound_web_analysis_preparation_run(
    output_root: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
) -> VerifiedCompactSkillBoundWebAnalysisPreparationRun:
    """Plan first, then persist one inert Run under a freshly pinned output root."""

    try:
        if active_pinned_workspace_identity() is not None:
            raise ValueError(
                "Public preparation creation cannot reload immutable inputs inside an active "
                "output workspace"
            )
        _require_disjoint_preparation_output(
            output_root,
            skill_run=skill_run,
            capacity_run=capacity_run,
        )
        plan = plan_compact_skill_bound_web_analysis_call(
            skill_run=skill_run,
            capacity_run=capacity_run,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_capacity_run_id=expected_capacity_run_id,
            expected_capacity_root_digest=expected_capacity_root_digest,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_capacity_proof_digest=expected_capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                expected_capacity_model_materialization_attestation_digest
            ),
            expected_transport_pin_digest=expected_transport_pin_digest,
        )

        pinned = PinnedOutputRoot.create(output_root)
        with pinned, pinned.activate():
            created = _create_compact_skill_bound_web_analysis_preparation_run_in_workspace(
                Path("."),
                plan=plan,
            )
            pinned.require_original_path_identity()
            absolute_run_path = (
                created.run_path
                if created.run_path.is_absolute()
                else pinned.path / created.run_path
            )
            return replace(created, run_path=absolute_run_path)
    except CompactSkillBoundWebAnalysisLivePreparationError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisLivePreparationError(
            "Compact Skill-bound Web analysis preparation output failed closed"
        ) from exc


def _create_compact_skill_bound_web_analysis_preparation_run_in_workspace(
    output_root: Path,
    *,
    plan: PlannedCompactSkillBoundWebAnalysisCall,
) -> VerifiedCompactSkillBoundWebAnalysisPreparationRun:
    """Persist exactly three inert artifacts, two events, and one seal."""

    try:
        if type(plan) is not PlannedCompactSkillBoundWebAnalysisCall:
            raise TypeError("Preparation persistence requires the exact precomputed plan")
        store = RunStore.create(output_root, _CAMPAIGN_NAME)
        store.append_event(_STARTED_EVENT, _started_payload(plan))
        store.write_json_create_only(
            _REQUEST_PATH,
            plan.live_request.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _PREPARATION_PATH,
            plan.preparation.model_dump(mode="json", by_alias=True),
        )
        index = _index_for(store.run_id, plan)
        store.write_json_create_only(
            _INDEX_PATH,
            index.model_dump(mode="json", by_alias=True),
        )
        store.append_event(_COMPLETED_EVENT, _completed_payload(plan, index))
        seal = store.seal()
        return _load_verified_compact_skill_bound_web_analysis_preparation_against_plan(
            store.path,
            expected_run_id=store.run_id,
            expected_root_digest=seal.root_digest,
            expected_plan=plan,
        )
    except CompactSkillBoundWebAnalysisLivePreparationError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisLivePreparationError(
            "Compact Skill-bound Web analysis preparation Run creation failed closed"
        ) from exc


def _load_exact_json(
    snapshot: VerifiedRunSnapshot,
    path: str,
    *,
    label: str,
) -> dict[str, object]:
    raw_bytes = snapshot.artifacts[path]
    raw = parse_strict_json_bytes(
        raw_bytes,
        label=label,
        max_bytes=_ARTIFACT_LIMITS[path],
        max_depth=32,
        max_nodes=100_000,
    )
    if type(raw) is not dict or _artifact_wire(raw) != raw_bytes:
        raise ValueError(f"{label} wire is not canonical Run JSON")
    return cast(dict[str, object], raw)


def _require_run_shape(
    snapshot: VerifiedRunSnapshot,
    *,
    expected_root_digest: str,
) -> None:
    artifacts = tuple(artifact for seal in snapshot.seals for artifact in seal.artifacts)
    paths = tuple(artifact.path for artifact in artifacts)
    if (
        snapshot.verification.root_digest != expected_root_digest
        or snapshot.verification.seal_count != 1
        or snapshot.verification.event_count != 2
        or snapshot.verification.artifact_count != 3
        or len(snapshot.seals) != 1
        or len(artifacts) != 3
        or len(set(paths)) != 3
        or set(paths) != _EXPECTED_ARTIFACTS
        or any(
            artifact.media_type != "application/json"
            or not 1 <= artifact.size_bytes <= _ARTIFACT_LIMITS[artifact.path]
            for artifact in artifacts
        )
        or len(snapshot.events) != 2
        or tuple(event.event_type for event in snapshot.events)
        != (_STARTED_EVENT, _COMPLETED_EVENT)
    ):
        raise ValueError("Compact live preparation sealed layout or events differ")


def load_verified_compact_skill_bound_web_analysis_preparation(
    run_path: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    expected_run_id: str,
    expected_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_capacity_run_id: str,
    expected_capacity_root_digest: str,
    expected_capacity_pin_digest: str,
    expected_capacity_proof_digest: str,
    expected_capacity_model_materialization_attestation_digest: str,
    expected_transport_pin_digest: str,
) -> VerifiedCompactSkillBoundWebAnalysisPreparationRun:
    """Strictly reload preparation plus its exact Capacity v2 authority."""

    try:
        _require_anchor(expected_run_id, label="preparation Run ID", run_id=True)
        _require_anchor(expected_root_digest, label="preparation Run root")
        expected_plan = plan_compact_skill_bound_web_analysis_call(
            skill_run=skill_run,
            capacity_run=capacity_run,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_capacity_run_id=expected_capacity_run_id,
            expected_capacity_root_digest=expected_capacity_root_digest,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_capacity_proof_digest=expected_capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                expected_capacity_model_materialization_attestation_digest
            ),
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        return _load_verified_compact_skill_bound_web_analysis_preparation_against_plan(
            run_path,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
            expected_plan=expected_plan,
        )
    except CompactSkillBoundWebAnalysisLivePreparationError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisLivePreparationError(
            "Compact Skill-bound Web analysis preparation verification failed closed"
        ) from exc


def _load_verified_compact_skill_bound_web_analysis_preparation_against_plan(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
    expected_plan: PlannedCompactSkillBoundWebAnalysisCall,
) -> VerifiedCompactSkillBoundWebAnalysisPreparationRun:
    """Reload only the output Run against a precomputed immutable-input plan."""

    try:
        _require_anchor(expected_run_id, label="preparation Run ID", run_id=True)
        _require_anchor(expected_root_digest, label="preparation Run root")
        if type(expected_plan) is not PlannedCompactSkillBoundWebAnalysisCall:
            raise TypeError("Preparation verification requires the exact precomputed plan")
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        _require_run_shape(initial, expected_root_digest=expected_root_digest)
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=dict(_ARTIFACT_LIMITS),
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed compact live preparation changed while artifacts were loaded",
        )
        request_raw = _load_exact_json(
            loaded,
            _REQUEST_PATH,
            label="compact live request artifact",
        )
        preparation_raw = _load_exact_json(
            loaded,
            _PREPARATION_PATH,
            label="compact live preparation artifact",
        )
        index_raw = _load_exact_json(
            loaded,
            _INDEX_PATH,
            label="compact live preparation Index artifact",
        )
        live_request = CompactSkillBoundWebAnalysisLiveRequest.model_validate(request_raw)
        preparation = CompactSkillBoundWebAnalysisPreparation.model_validate(preparation_raw)
        index = CompactSkillBoundWebAnalysisPreparationIndex.model_validate(index_raw)
        if (
            live_request.model_dump(mode="json", by_alias=True) != request_raw
            or preparation.model_dump(mode="json", by_alias=True) != preparation_raw
            or index.model_dump(mode="json", by_alias=True) != index_raw
        ):
            raise ValueError("Compact live preparation artifact fields differ")
        expected_index = _index_for(expected_run_id, expected_plan)
        started, completed = loaded.events
        if (
            live_request != expected_plan.live_request
            or preparation != expected_plan.preparation
            or index != expected_index
            or started.payload != _started_payload(expected_plan)
            or completed.payload != _completed_payload(expected_plan, expected_index)
        ):
            raise ValueError("Compact live preparation lineage or audit differs")
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            loaded,
            final,
            message="sealed compact live preparation changed after verification",
        )
        return VerifiedCompactSkillBoundWebAnalysisPreparationRun(
            run_id=expected_run_id,
            run_path=final.run_path,
            root_digest=expected_root_digest,
            live_request=live_request,
            preparation=preparation,
            index=index,
            started_event_hash=started.event_hash,
            completed_event_hash=completed.event_hash,
        )
    except CompactSkillBoundWebAnalysisLivePreparationError:
        raise
    except Exception as exc:
        raise CompactSkillBoundWebAnalysisLivePreparationError(
            "Compact Skill-bound Web analysis preparation verification failed closed"
        ) from exc


__all__ = [
    "COMPACT_LIVE_PREPARATION_STATUS",
    "CompactSkillBoundWebAnalysisLivePreparationError",
    "CompactSkillBoundWebAnalysisLiveRequest",
    "CompactSkillBoundWebAnalysisPreparation",
    "CompactSkillBoundWebAnalysisPreparationIndex",
    "CompactSkillBoundWebAnalysisZeroDispatchState",
    "PlannedCompactSkillBoundWebAnalysisCall",
    "VerifiedCompactSkillBoundWebAnalysisPreparationRun",
    "create_compact_skill_bound_web_analysis_preparation_run",
    "load_verified_compact_skill_bound_web_analysis_preparation",
    "plan_compact_skill_bound_web_analysis_call",
]
