"""Attested offline tokenizer capacity proof for compact Skill-bound Web analysis.

This additive reader and producer preserve the v1 capacity wire while requiring a
descriptor-bound Docker-volume materialization attestation.  The module remains
preparation-only: it cannot invoke the model, dispatch a Provider request, contact
a target, or mint execution authority.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.effectiveness.suite import ModelPin, RuntimePin
from pajin.domain.models import StrictModel
from pajin.providers.models import ProviderChatRequest
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.web_assessment.analysis_capacity import (
    WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET,
    WEB_ANALYSIS_COMPLETION_TOKENS,
    WEB_ANALYSIS_CONTEXT_TOKENS,
    OfflineTokenizerBackend,
    SubprocessLlamaCppTokenizerBackend,
    TokenizerModelMountObservation,
    WebAnalysisCapacityError,
    WebAnalysisCapacityEvidence,
    WebAnalysisCapacityIndex,
    WebAnalysisCapacityPin,
    WebAnalysisCapacityProof,
    _artifact_wire,
    _canonical_projection,
    _canonical_request,
    _conservative_campaign_prompt_bound,
    _derived_skill_inputs,
    _digest,
    _json_wire,
    _measure_capacity,
    _require_sentinels,
    build_web_analysis_capacity_pin,
)
from pajin.web_assessment.analysis_skill_compact import (
    COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    COMPACT_SKILL_BOUND_USER_SENTINEL,
    CompactSkillBoundWebAnalysisProjection,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
)

WEB_ANALYSIS_CAPACITY_V2_PIN_API_VERSION: Final = "pajin.dev/web-analysis-capacity-pin/v1alpha2"
WEB_ANALYSIS_CAPACITY_V2_EVIDENCE_API_VERSION: Final = (
    "pajin.dev/web-analysis-capacity-evidence/v1alpha2"
)
WEB_ANALYSIS_CAPACITY_V2_PROOF_API_VERSION: Final = "pajin.dev/web-analysis-capacity-proof/v1alpha2"
WEB_ANALYSIS_CAPACITY_V2_INDEX_API_VERSION: Final = "pajin.dev/web-analysis-capacity-index/v1alpha2"
WEB_ANALYSIS_CAPACITY_V2_RUN_API_VERSION: Final = (
    "pajin.dev/verified-web-analysis-capacity-run/v1alpha2"
)
MODEL_MATERIALIZATION_ATTESTATION_API_VERSION: Final = (
    "pajin.dev/web-analysis-model-materialization-attestation/v1alpha1"
)

_PROJECTION_PATH = "compact-projection.json"
_PIN_PATH = "capacity-pin.json"
_EVIDENCE_PATH = "capacity-evidence.json"
_PROOF_PATH = "capacity-proof.json"
_INDEX_PATH = "capacity-index.json"
_ARTIFACT_LIMITS: Final = {
    _PROJECTION_PATH: 2 * 1024 * 1024,
    _PIN_PATH: 128 * 1024,
    _EVIDENCE_PATH: 8 * 1024 * 1024,
    _PROOF_PATH: 256 * 1024,
    _INDEX_PATH: 128 * 1024,
}
_EXPECTED_ARTIFACTS = frozenset(_ARTIFACT_LIMITS)
_STARTED_EVENT = "web-analysis.capacity-proof-v2.started"
_MODEL_MOUNT_ATTESTED_EVENT = "web-analysis.capacity-proof-v2.model-mount-attested"
_COMPLETED_EVENT = "web-analysis.capacity-proof-v2.completed"
_CAMPAIGN_NAME = "web-analysis-capacity-proof"
_MAX_TOKENIZER_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_PROMPT_BYTES = 4 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageID = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis capacity authority markers must be literal false")
    return False


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Web analysis capacity attestation markers must be literal true")
    return True


class _FrozenCapacityV2Model(StrictModel):
    """Strict immutable model with an explicit local config for v2 wires."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class _NoAuthorityV2Model(_FrozenCapacityV2Model):
    provider_dispatch_authority: Literal[False] = Field(
        default=False, alias="providerDispatchAuthority"
    )
    target_request_authority: Literal[False] = Field(default=False, alias="targetRequestAuthority")
    scope_expansion_authority: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthority"
    )
    tool_request_authority: Literal[False] = Field(default=False, alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(default=False, alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthority"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(
        default=False, alias="reportDeliveryAuthority"
    )

    @field_validator(
        "provider_dispatch_authority",
        "target_request_authority",
        "scope_expansion_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        "graph_admission_authority",
        "finding_authority",
        "report_delivery_authority",
        mode="before",
    )
    @classmethod
    def require_no_authority(cls, value: object) -> Literal[False]:
        return _literal_false(value)


class WebAnalysisCapacityV2Pin(WebAnalysisCapacityPin):
    """Additive v2 capacity Pin; all v1 fields retain their exact meaning."""

    api_version: Literal["pajin.dev/web-analysis-capacity-pin/v1alpha2"] = Field(  # type: ignore[assignment]  # Pydantic versioned wire override
        default=WEB_ANALYSIS_CAPACITY_V2_PIN_API_VERSION,
        alias="apiVersion",
    )
    model_materialization_policy_digest: _Sha256 = Field(alias="modelMaterializationPolicyDigest")

    @model_validator(mode="after")
    def bind_model_materialization_policy(self) -> Self:
        if self.model_materialization_policy_digest != (_model_materialization_policy_digest()):
            raise ValueError("Model materialization policy digest differs")
        return self


class WebAnalysisModelMaterializationAttestation(_NoAuthorityV2Model):
    """Secret-free attestation of one pinned model materialization."""

    api_version: Literal["pajin.dev/web-analysis-model-materialization-attestation/v1alpha1"] = (
        Field(default=MODEL_MATERIALIZATION_ATTESTATION_API_VERSION, alias="apiVersion")
    )
    kind: Literal["WebAnalysisModelMaterializationAttestation"] = (
        "WebAnalysisModelMaterializationAttestation"
    )
    attestation_digest: str = Field(default="", alias="attestationDigest", max_length=64)
    model_pin_digest: _Sha256 = Field(alias="modelPinDigest")
    expected_model_sha256: _Sha256 = Field(alias="expectedModelSha256")
    expected_model_size_bytes: int = Field(alias="expectedModelSizeBytes", ge=1)
    staged_model_sha256: _Sha256 = Field(alias="stagedModelSha256")
    staged_model_size_bytes: int = Field(alias="stagedModelSizeBytes", ge=1)
    staged_model_uid: Literal[10001] = Field(alias="stagedModelUid")
    staged_model_gid: Literal[10001] = Field(alias="stagedModelGid")
    staged_model_mode: Literal["0400"] = Field(alias="stagedModelMode")
    mounted_model_sha256: _Sha256 = Field(alias="mountedModelSha256")
    mounted_model_size_bytes: int = Field(alias="mountedModelSizeBytes", ge=1)
    mounted_model_uid: Literal[10001] = Field(alias="mountedModelUid")
    mounted_model_gid: Literal[10001] = Field(alias="mountedModelGid")
    mounted_model_mode: Literal["0400"] = Field(alias="mountedModelMode")
    tokenizer_image_id: _ImageID = Field(alias="tokenizerImageId")
    staging_strategy: Literal["descriptor-to-docker-volume"] = Field(alias="stagingStrategy")
    materialization_kind: Literal["docker-copy"] = Field(alias="materializationKind")
    mount_type: Literal["volume"] = Field(alias="mountType")
    mount_destination: Literal["/models"] = Field(alias="mountDestination")
    read_only: Literal[True] = Field(alias="readOnly")
    digest_algorithm: Literal["sha256"] = Field(alias="digestAlgorithm")
    attested_before_tokenizer_endpoints: Literal[True] = Field(
        alias="attestedBeforeTokenizerEndpoints"
    )
    runtime_user_read_verified: Literal[True] = Field(alias="runtimeUserReadVerified")
    cleanup_required: Literal[True] = Field(alias="cleanupRequired")

    @field_validator(
        "read_only",
        "attested_before_tokenizer_endpoints",
        "runtime_user_read_verified",
        "cleanup_required",
        mode="before",
    )
    @classmethod
    def require_attestation_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @model_validator(mode="after")
    def bind_attestation(self) -> Self:
        if not (
            self.expected_model_sha256 == self.staged_model_sha256 == self.mounted_model_sha256
        ):
            raise ValueError("Model materialization SHA-256 observations differ")
        if not (
            self.expected_model_size_bytes
            == self.staged_model_size_bytes
            == self.mounted_model_size_bytes
        ):
            raise ValueError("Model materialization size observations differ")
        if not (
            self.staged_model_uid == self.mounted_model_uid == 10001
            and self.staged_model_gid == self.mounted_model_gid == 10001
            and self.staged_model_mode == self.mounted_model_mode == "0400"
        ):
            raise ValueError("Model materialization runtime metadata differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"attestation_digest"})
        digest = _digest(
            "model-materialization-attestation/v2",
            _json_wire(
                material,
                label="model materialization attestation",
                max_bytes=128 * 1024,
            ),
        )
        if self.attestation_digest and self.attestation_digest != digest:
            raise ValueError("Model materialization attestation digest differs")
        object.__setattr__(self, "attestation_digest", digest)
        return self


class WebAnalysisCapacityV2Evidence(WebAnalysisCapacityEvidence):
    api_version: Literal["pajin.dev/web-analysis-capacity-evidence/v1alpha2"] = Field(  # type: ignore[assignment]  # Pydantic versioned wire override
        default=WEB_ANALYSIS_CAPACITY_V2_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    model_materialization_attestation: WebAnalysisModelMaterializationAttestation = Field(
        alias="modelMaterializationAttestation"
    )


class WebAnalysisCapacityV2Proof(WebAnalysisCapacityProof):
    api_version: Literal["pajin.dev/web-analysis-capacity-proof/v1alpha2"] = Field(  # type: ignore[assignment]  # Pydantic versioned wire override
        default=WEB_ANALYSIS_CAPACITY_V2_PROOF_API_VERSION,
        alias="apiVersion",
    )
    model_materialization_attestation_digest: _Sha256 = Field(
        alias="modelMaterializationAttestationDigest"
    )


class WebAnalysisCapacityV2Index(WebAnalysisCapacityIndex):
    api_version: Literal["pajin.dev/web-analysis-capacity-index/v1alpha2"] = Field(  # type: ignore[assignment]  # Pydantic versioned wire override
        default=WEB_ANALYSIS_CAPACITY_V2_INDEX_API_VERSION,
        alias="apiVersion",
    )
    model_materialization_attestation_digest: _Sha256 = Field(
        alias="modelMaterializationAttestationDigest"
    )


class VerifiedWebAnalysisCapacityV2Run(_FrozenCapacityV2Model):
    api_version: Literal["pajin.dev/verified-web-analysis-capacity-run/v1alpha2"] = Field(
        default=WEB_ANALYSIS_CAPACITY_V2_RUN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["VerifiedWebAnalysisCapacityRun"] = "VerifiedWebAnalysisCapacityRun"
    run_id: Annotated[str, Field(pattern=_RUN_ID_PATTERN, max_length=64)] = Field(alias="runId")
    run_path: Path = Field(alias="runPath")
    root_digest: _Sha256 = Field(alias="rootDigest")
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    pin: WebAnalysisCapacityV2Pin
    evidence: WebAnalysisCapacityV2Evidence
    proof: WebAnalysisCapacityV2Proof
    index: WebAnalysisCapacityV2Index
    model_materialization_attestation_digest: _Sha256 = Field(
        alias="modelMaterializationAttestationDigest"
    )
    started_event_hash: _Sha256 = Field(alias="startedEventHash")
    model_mount_attested_event_hash: _Sha256 = Field(alias="modelMountAttestedEventHash")
    completed_event_hash: _Sha256 = Field(alias="completedEventHash")

    @model_validator(mode="after")
    def bind_verified_run(self) -> Self:
        attestation_digest = self.evidence.model_materialization_attestation.attestation_digest
        if (
            self.index.run_id != self.run_id
            or self.index.projection_digest != self.projection_digest
            or self.index.pin_digest != self.pin.pin_digest
            or self.index.evidence_digest != self.evidence.evidence_digest
            or self.index.proof_digest != self.proof.proof_digest
            or self.proof.pin_digest != self.pin.pin_digest
            or self.proof.evidence_digest != self.evidence.evidence_digest
            or self.model_materialization_attestation_digest != attestation_digest
            or self.proof.model_materialization_attestation_digest != attestation_digest
            or self.index.model_materialization_attestation_digest != attestation_digest
        ):
            raise ValueError("Verified v2 capacity Run lineage differs")
        return self


class OfflineTokenizerV2Backend(OfflineTokenizerBackend, Protocol):
    """Tokenizer backend that exposes its pre-endpoint model mount observation."""

    def model_mount_observation(self) -> TokenizerModelMountObservation: ...


def _runtime_v1_pin(pin: WebAnalysisCapacityV2Pin) -> WebAnalysisCapacityPin:
    payload = pin.model_dump(mode="json", by_alias=True)
    payload["apiVersion"] = "pajin.dev/web-analysis-capacity-pin/v1alpha1"
    payload["pinDigest"] = ""
    del payload["modelMaterializationPolicyDigest"]
    return WebAnalysisCapacityPin.model_validate(payload)


def _model_materialization_policy_digest() -> str:
    policy = {
        "policy": "pajin.web-analysis.model-materialization-policy/v1",
        "stagingStrategy": "descriptor-to-docker-volume",
        "materializationKind": "docker-copy",
        "digestAlgorithm": "sha256",
        "expectedIdentity": {"digestRequired": True, "sizeRequired": True},
        "stagedIdentity": {
            "digestMustEqualExpected": True,
            "sizeMustEqualExpected": True,
        },
        "mountedIdentity": {
            "digestMustEqualExpected": True,
            "sizeMustEqualExpected": True,
        },
        "sameDockerManagedVolume": True,
        "normalization": {
            "seedNetwork": "none",
            "seedReadOnlyRootfs": True,
            "seedCapabilityDrop": ["ALL"],
            "seedCapabilityAdd": ["CAP_CHOWN"],
            "runtimeUid": 10001,
            "runtimeGid": 10001,
            "mode": "0400",
            "runtimeUserReadVerified": True,
        },
        "mount": {"type": "volume", "destination": "/models", "readOnly": True},
        "attestedBeforeTokenizerEndpoints": True,
        "cleanupRequired": True,
    }
    return _digest(
        "model-materialization-policy/v1",
        _json_wire(
            policy,
            label="model materialization policy",
            max_bytes=64 * 1024,
        ),
    )


def _canonical_v2_pin(pin: object) -> WebAnalysisCapacityV2Pin:
    if type(pin) is not WebAnalysisCapacityV2Pin:
        raise WebAnalysisCapacityError("Capacity v2 proof requires the exact v2 Pin")
    value = pin
    return WebAnalysisCapacityV2Pin.model_validate(value.model_dump(mode="json", by_alias=True))


def build_web_analysis_capacity_v2_pin(
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    projection: object,
    chat_request: ProviderChatRequest,
    *,
    runtime: RuntimePin,
    model_pin: ModelPin,
    transport_pin_digest: str,
    conservative_campaign_prompt_tokens: int,
) -> WebAnalysisCapacityV2Pin:
    """Build the additive v2 Pin without changing any v1 reader or wire."""

    v1_pin = build_web_analysis_capacity_pin(
        skill_run,
        projection,
        chat_request,
        runtime=runtime,
        model_pin=model_pin,
        transport_pin_digest=transport_pin_digest,
        conservative_campaign_prompt_tokens=conservative_campaign_prompt_tokens,
    )
    payload = v1_pin.model_dump(mode="json", by_alias=True)
    payload["apiVersion"] = WEB_ANALYSIS_CAPACITY_V2_PIN_API_VERSION
    payload["pinDigest"] = ""
    payload["modelMaterializationPolicyDigest"] = _model_materialization_policy_digest()
    return WebAnalysisCapacityV2Pin.model_validate(payload)


def _attestation_from_observation(
    observation: object,
    *,
    pin: WebAnalysisCapacityV2Pin,
) -> WebAnalysisModelMaterializationAttestation:
    if type(observation) is not TokenizerModelMountObservation:
        raise WebAnalysisCapacityError(
            "Capacity v2 requires the exact tokenizer model mount observation"
        )
    value = observation
    attestation = WebAnalysisModelMaterializationAttestation(
        modelPinDigest=value.model_pin_digest,
        expectedModelSha256=value.expected_model_sha256,
        expectedModelSizeBytes=value.expected_model_size_bytes,
        stagedModelSha256=value.staged_model_sha256,
        stagedModelSizeBytes=value.staged_model_size_bytes,
        stagedModelUid=value.staged_model_uid,
        stagedModelGid=value.staged_model_gid,
        stagedModelMode=value.staged_model_mode,
        mountedModelSha256=value.mounted_model_sha256,
        mountedModelSizeBytes=value.mounted_model_size_bytes,
        mountedModelUid=value.mounted_model_uid,
        mountedModelGid=value.mounted_model_gid,
        mountedModelMode=value.mounted_model_mode,
        tokenizerImageId=value.tokenizer_image_id,
        stagingStrategy=value.staging_strategy,
        materializationKind=value.materialization_kind,
        mountType=value.mount_type,
        mountDestination=value.mount_destination,
        readOnly=value.mount_read_only,
        digestAlgorithm=value.digest_algorithm,
        attestedBeforeTokenizerEndpoints=value.attested_before_tokenizer_requests,
        runtimeUserReadVerified=value.runtime_user_read_verified,
        cleanupRequired=value.cleanup_required,
    )
    if (
        attestation.model_pin_digest != pin.model_pin_digest
        or attestation.expected_model_sha256 != pin.model_sha256
        or attestation.expected_model_size_bytes != pin.model_size_bytes
        or attestation.tokenizer_image_id != pin.tokenizer_image_id
    ):
        raise WebAnalysisCapacityError(
            "Tokenizer model mount attestation differs from the capacity Pin"
        )
    return attestation


def _measure_capacity_v2(
    *,
    request: ProviderChatRequest,
    pin: WebAnalysisCapacityV2Pin,
    runtime_pin: WebAnalysisCapacityPin,
    backend: OfflineTokenizerV2Backend,
    attestation: WebAnalysisModelMaterializationAttestation,
    system_sentinel: str,
    user_sentinel: str,
) -> tuple[WebAnalysisCapacityV2Evidence, WebAnalysisCapacityV2Proof]:
    v1_evidence, v1_proof = _measure_capacity(
        request=request,
        pin=runtime_pin,
        backend=backend,
        system_sentinel=system_sentinel,
        user_sentinel=user_sentinel,
    )
    evidence_payload = v1_evidence.model_dump(mode="json", by_alias=True)
    evidence_payload.update(
        {
            "apiVersion": WEB_ANALYSIS_CAPACITY_V2_EVIDENCE_API_VERSION,
            "evidenceDigest": "",
            "modelMaterializationAttestation": attestation.model_dump(mode="json", by_alias=True),
        }
    )
    evidence = WebAnalysisCapacityV2Evidence.model_validate(evidence_payload)
    proof_payload = v1_proof.model_dump(mode="json", by_alias=True)
    proof_payload.update(
        {
            "apiVersion": WEB_ANALYSIS_CAPACITY_V2_PROOF_API_VERSION,
            "proofDigest": "",
            "pinDigest": pin.pin_digest,
            "evidenceDigest": evidence.evidence_digest,
            "modelMaterializationAttestationDigest": attestation.attestation_digest,
        }
    )
    return evidence, WebAnalysisCapacityV2Proof.model_validate(proof_payload)


def _model_mount_event_payload(
    attestation: WebAnalysisModelMaterializationAttestation,
) -> dict[str, object]:
    return {
        "modelMaterializationAttestationDigest": attestation.attestation_digest,
        "modelPinDigest": attestation.model_pin_digest,
        "expectedModelSha256": attestation.expected_model_sha256,
        "expectedModelSizeBytes": attestation.expected_model_size_bytes,
        "stagedModelSha256": attestation.staged_model_sha256,
        "stagedModelSizeBytes": attestation.staged_model_size_bytes,
        "stagedModelUid": attestation.staged_model_uid,
        "stagedModelGid": attestation.staged_model_gid,
        "stagedModelMode": attestation.staged_model_mode,
        "mountedModelSha256": attestation.mounted_model_sha256,
        "mountedModelSizeBytes": attestation.mounted_model_size_bytes,
        "mountedModelUid": attestation.mounted_model_uid,
        "mountedModelGid": attestation.mounted_model_gid,
        "mountedModelMode": attestation.mounted_model_mode,
        "tokenizerImageId": attestation.tokenizer_image_id,
        "stagingStrategy": attestation.staging_strategy,
        "materializationKind": attestation.materialization_kind,
        "mountType": attestation.mount_type,
        "mountDestination": attestation.mount_destination,
        "readOnly": True,
        "digestAlgorithm": attestation.digest_algorithm,
        "attestedBeforeTokenizerEndpoints": True,
        "runtimeUserReadVerified": True,
        "cleanupRequired": True,
        "modelInferencePerformed": False,
        "providerDispatch": False,
        "targetRequests": 0,
    }


def create_web_analysis_capacity_v2_run(
    output_root: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    projection: object,
    chat_request: ProviderChatRequest,
    pin: WebAnalysisCapacityV2Pin,
    tokenizer_backend: SubprocessLlamaCppTokenizerBackend,
    system_sentinel: str = COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    user_sentinel: str = COMPACT_SKILL_BOUND_USER_SENTINEL,
) -> VerifiedWebAnalysisCapacityV2Run:
    """Mint v2 only through the exact descriptor-bound production backend."""

    if type(tokenizer_backend) is not SubprocessLlamaCppTokenizerBackend:
        raise WebAnalysisCapacityError(
            "Production capacity v2 proof requires the exact pinned llama.cpp backend"
        )
    return _create_web_analysis_capacity_v2_run_with_backend(
        output_root,
        skill_run=skill_run,
        projection=projection,
        chat_request=chat_request,
        pin=pin,
        tokenizer_backend=tokenizer_backend,
        system_sentinel=system_sentinel,
        user_sentinel=user_sentinel,
    )


def _create_web_analysis_capacity_v2_run_with_backend(
    output_root: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    projection: object,
    chat_request: ProviderChatRequest,
    pin: WebAnalysisCapacityV2Pin,
    tokenizer_backend: OfflineTokenizerV2Backend,
    system_sentinel: str = COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    user_sentinel: str = COMPACT_SKILL_BOUND_USER_SENTINEL,
) -> VerifiedWebAnalysisCapacityV2Run:
    """Internal deterministic seam; it is not a production producer."""

    try:
        canonical_projection = _canonical_projection(projection)
        canonical_request = _canonical_request(chat_request)
        canonical_pin = _canonical_v2_pin(pin)
        if (
            system_sentinel != COMPACT_SKILL_BOUND_SYSTEM_SENTINEL
            or user_sentinel != COMPACT_SKILL_BOUND_USER_SENTINEL
        ):
            raise WebAnalysisCapacityError(
                "Capacity v2 sentinels differ from compact code authority"
            )
        expected_projection, expected_request = _derived_skill_inputs(skill_run)
        if canonical_projection != expected_projection or canonical_request != expected_request:
            raise WebAnalysisCapacityError(
                "Capacity v2 inputs differ from the verified Skill snapshot"
            )
        projection_payload = canonical_projection.model_dump(mode="json", by_alias=True)
        projection_wire = _json_wire(
            projection_payload,
            label="compact projection",
            max_bytes=_ARTIFACT_LIMITS[_PROJECTION_PATH],
        )
        request_wire = _json_wire(
            canonical_request.model_dump(mode="json", by_alias=True),
            label="capacity request",
            max_bytes=_MAX_PROMPT_BYTES,
        )
        source = skill_run.snapshot.source_snapshot
        if (
            canonical_pin.compact_projection_digest
            != _digest("compact-projection", projection_wire)
            or canonical_pin.chat_request_digest != _digest("chat-request", request_wire)
            or canonical_pin.skill_run_id != skill_run.verification.run_id
            or canonical_pin.skill_run_root_digest != skill_run.verification.root_digest
            or canonical_pin.skill_projection_digest != skill_run.snapshot.snapshot_digest
            or canonical_pin.source_run_id != source.source_run_id
            or canonical_pin.source_root_digest != source.source_root_digest
            or canonical_pin.source_artifact_digest != source.source_index_digest
        ):
            raise WebAnalysisCapacityError("Capacity v2 Pin differs from projection or request")

        runtime_pin = _runtime_v1_pin(canonical_pin)
        store = RunStore.create(output_root, _CAMPAIGN_NAME)
        store.append_event(
            _STARTED_EVENT,
            {
                "pinDigest": canonical_pin.pin_digest,
                "projectionDigest": canonical_pin.compact_projection_digest,
                "requestDigest": canonical_pin.chat_request_digest,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            },
        )
        attestation: WebAnalysisModelMaterializationAttestation | None = None
        evidence: WebAnalysisCapacityV2Evidence | None = None
        proof: WebAnalysisCapacityV2Proof | None = None
        operation_error: BaseException | None = None
        try:
            tokenizer_backend.start(runtime_pin)
            attestation = _attestation_from_observation(
                tokenizer_backend.model_mount_observation(),
                pin=canonical_pin,
            )
            store.append_event(
                _MODEL_MOUNT_ATTESTED_EVENT,
                _model_mount_event_payload(attestation),
            )
            evidence, proof = _measure_capacity_v2(
                request=canonical_request,
                pin=canonical_pin,
                runtime_pin=runtime_pin,
                backend=tokenizer_backend,
                attestation=attestation,
                system_sentinel=system_sentinel,
                user_sentinel=user_sentinel,
            )
        except BaseException as exc:
            operation_error = exc

        cleanup_errors: list[BaseException] = []
        try:
            tokenizer_backend.cleanup()
        except BaseException as exc:
            cleanup_errors.append(exc)
        try:
            tokenizer_backend.verify_absent()
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            raise WebAnalysisCapacityError(
                "Offline tokenizer capacity v2 cleanup did not prove resource absence"
            ) from cleanup_errors[0]
        if operation_error is not None:
            raise WebAnalysisCapacityError(
                "Offline tokenizer capacity v2 measurement failed"
            ) from operation_error
        assert attestation is not None and evidence is not None and proof is not None

        store.write_json_create_only(_PROJECTION_PATH, projection_payload)
        store.write_json_create_only(
            _PIN_PATH,
            canonical_pin.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _EVIDENCE_PATH,
            evidence.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _PROOF_PATH,
            proof.model_dump(mode="json", by_alias=True),
        )
        index = WebAnalysisCapacityV2Index(
            runId=store.run_id,
            projectionDigest=canonical_pin.compact_projection_digest,
            pinDigest=canonical_pin.pin_digest,
            evidenceDigest=evidence.evidence_digest,
            proofDigest=proof.proof_digest,
            modelMaterializationAttestationDigest=attestation.attestation_digest,
        )
        store.write_json_create_only(
            _INDEX_PATH,
            index.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            _COMPLETED_EVENT,
            {
                "indexDigest": index.index_digest,
                "evidenceDigest": evidence.evidence_digest,
                "proofDigest": proof.proof_digest,
                "modelMaterializationAttestationDigest": attestation.attestation_digest,
                "promptTokens": proof.prompt_tokens,
                "totalTokens": proof.total_tokens,
                "remainingTokens": proof.remaining_tokens,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            },
        )
        seal = store.seal()
        return load_verified_web_analysis_capacity_v2_run(
            store.path,
            skill_run=skill_run,
            expected_run_id=store.run_id,
            expected_root_digest=seal.root_digest,
            expected_pin_digest=canonical_pin.pin_digest,
            expected_transport_pin_digest=canonical_pin.transport_pin_digest,
            expected_proof_digest=proof.proof_digest,
            expected_model_materialization_attestation_digest=(attestation.attestation_digest),
        )
    except WebAnalysisCapacityError:
        raise
    except Exception as exc:
        raise WebAnalysisCapacityError(
            "Web analysis capacity v2 Run creation failed closed"
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
        max_depth=40,
        max_nodes=100_000,
    )
    if type(raw) is not dict or _artifact_wire(raw) != raw_bytes:
        raise WebAnalysisCapacityError(f"{label} wire is not canonical Run JSON")
    return cast(dict[str, object], raw)


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _valid_run_id(value: str) -> bool:
    if len(value) != 29 or not value.startswith("run_"):
        return False
    date_time, separator, suffix = value[4:].partition("_")
    return (
        separator == "_"
        and len(date_time) == 16
        and date_time[8] == "T"
        and date_time[-1] == "Z"
        and date_time[:8].isdigit()
        and date_time[9:15].isdigit()
        and len(suffix) == 8
        and all(character in "0123456789abcdef" for character in suffix)
    )


def load_verified_web_analysis_capacity_v2_run(
    run_path: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    expected_run_id: str,
    expected_root_digest: str,
    expected_pin_digest: str,
    expected_transport_pin_digest: str,
    expected_proof_digest: str,
    expected_model_materialization_attestation_digest: str,
) -> VerifiedWebAnalysisCapacityV2Run:
    """Strict-reload v2 from six independent Run, Pin, and proof anchors."""

    try:
        if (
            not _valid_run_id(expected_run_id)
            or not _valid_sha256(expected_root_digest)
            or not _valid_sha256(expected_pin_digest)
            or not _valid_sha256(expected_transport_pin_digest)
            or not _valid_sha256(expected_proof_digest)
            or not _valid_sha256(expected_model_materialization_attestation_digest)
        ):
            raise ValueError("Capacity v2 independent anchor is invalid")
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        sealed_artifacts = tuple(artifact for seal in initial.seals for artifact in seal.artifacts)
        sealed_paths = {artifact.path for artifact in sealed_artifacts}
        if (
            initial.verification.root_digest != expected_root_digest
            or initial.verification.seal_count != 1
            or initial.verification.event_count != 3
            or initial.verification.artifact_count != 5
            or len(initial.seals) != 1
            or len(sealed_artifacts) != 5
            or sealed_paths != _EXPECTED_ARTIFACTS
            or any(
                artifact.media_type != "application/json"
                or not 1 <= artifact.size_bytes <= _ARTIFACT_LIMITS[artifact.path]
                for artifact in sealed_artifacts
            )
            or len(initial.events) != 3
            or tuple(event.event_type for event in initial.events)
            != (_STARTED_EVENT, _MODEL_MOUNT_ATTESTED_EVENT, _COMPLETED_EVENT)
        ):
            raise ValueError("Capacity v2 sealed layout or events differ")

        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=_ARTIFACT_LIMITS,
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed capacity v2 Run changed while artifacts were loaded",
        )
        projection_raw = _load_exact_json(
            loaded,
            _PROJECTION_PATH,
            label="compact projection artifact",
        )
        projection = CompactSkillBoundWebAnalysisProjection.model_validate(projection_raw)
        if projection.model_dump(mode="json", by_alias=True) != projection_raw:
            raise ValueError("Capacity v2 compact projection wire fields differ")
        expected_projection, expected_request = _derived_skill_inputs(skill_run)
        if projection != expected_projection:
            raise ValueError("Capacity v2 projection differs from the verified Skill Run")

        projection_payload = projection.model_dump(mode="json", by_alias=True)
        projection_digest = _digest(
            "compact-projection",
            _json_wire(
                projection_payload,
                label="compact projection",
                max_bytes=_ARTIFACT_LIMITS[_PROJECTION_PATH],
            ),
        )
        request_wire = _json_wire(
            expected_request.model_dump(mode="json", by_alias=True),
            label="capacity request",
            max_bytes=_MAX_PROMPT_BYTES,
        )
        messages_wire = _json_wire(
            [
                message.model_dump(mode="json", by_alias=True, exclude_none=True)
                for message in expected_request.messages
            ],
            label="capacity messages",
            max_bytes=_MAX_PROMPT_BYTES,
        )

        pin_raw = _load_exact_json(loaded, _PIN_PATH, label="capacity v2 Pin artifact")
        evidence_raw = _load_exact_json(
            loaded,
            _EVIDENCE_PATH,
            label="capacity v2 Evidence artifact",
        )
        proof_raw = _load_exact_json(loaded, _PROOF_PATH, label="capacity v2 Proof artifact")
        index_raw = _load_exact_json(loaded, _INDEX_PATH, label="capacity v2 Index artifact")
        pin = WebAnalysisCapacityV2Pin.model_validate(pin_raw)
        evidence = WebAnalysisCapacityV2Evidence.model_validate(evidence_raw)
        proof = WebAnalysisCapacityV2Proof.model_validate(proof_raw)
        index = WebAnalysisCapacityV2Index.model_validate(index_raw)
        if (
            pin.model_dump(mode="json", by_alias=True) != pin_raw
            or evidence.model_dump(mode="json", by_alias=True) != evidence_raw
            or proof.model_dump(mode="json", by_alias=True) != proof_raw
            or index.model_dump(mode="json", by_alias=True) != index_raw
        ):
            raise ValueError("Capacity v2 artifact wire fields differ")

        _require_sentinels(
            expected_request,
            evidence.formatted_prompt,
            system_sentinel=COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
            user_sentinel=COMPACT_SKILL_BOUND_USER_SENTINEL,
        )
        formatted_prompt_wire = evidence.formatted_prompt.encode("utf-8")
        chat_template_wire = evidence.chat_template.encode("utf-8")
        token_sequence_wire = _json_wire(
            list(evidence.token_ids),
            label="token sequence",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
        )
        conservative_prompt_bound = _conservative_campaign_prompt_bound(
            expected_request,
            model_id=pin.model_id,
        )
        attestation = evidence.model_materialization_attestation
        source = skill_run.snapshot.source_snapshot
        started, mount_attested, completed = loaded.events
        if (
            pin.pin_digest != expected_pin_digest
            or pin.transport_pin_digest != expected_transport_pin_digest
            or proof.proof_digest != expected_proof_digest
            or attestation.attestation_digest != expected_model_materialization_attestation_digest
            or pin.skill_run_id != skill_run.verification.run_id
            or pin.skill_run_root_digest != skill_run.verification.root_digest
            or pin.skill_projection_digest != skill_run.snapshot.snapshot_digest
            or pin.source_run_id != source.source_run_id
            or pin.source_root_digest != source.source_root_digest
            or pin.source_artifact_digest != source.source_index_digest
            or pin.compact_projection_digest != projection_digest
            or pin.chat_request_digest != _digest("chat-request", request_wire)
            or attestation.model_pin_digest != pin.model_pin_digest
            or attestation.expected_model_sha256 != pin.model_sha256
            or attestation.staged_model_sha256 != pin.model_sha256
            or attestation.mounted_model_sha256 != pin.model_sha256
            or attestation.expected_model_size_bytes != pin.model_size_bytes
            or attestation.staged_model_size_bytes != pin.model_size_bytes
            or attestation.mounted_model_size_bytes != pin.model_size_bytes
            or attestation.staged_model_uid != 10001
            or attestation.staged_model_gid != 10001
            or attestation.staged_model_mode != "0400"
            or attestation.mounted_model_uid != 10001
            or attestation.mounted_model_gid != 10001
            or attestation.mounted_model_mode != "0400"
            or attestation.runtime_user_read_verified is not True
            or attestation.tokenizer_image_id != pin.tokenizer_image_id
            or proof.pin_digest != pin.pin_digest
            or proof.evidence_digest != evidence.evidence_digest
            or proof.model_materialization_attestation_digest != attestation.attestation_digest
            or proof.request_digest != pin.chat_request_digest
            or proof.request_bytes != len(request_wire)
            or proof.message_digest != _digest("messages", messages_wire)
            or proof.message_bytes != len(messages_wire)
            or proof.formatted_prompt_digest != _digest("formatted-prompt", formatted_prompt_wire)
            or proof.formatted_prompt_bytes != len(formatted_prompt_wire)
            or proof.chat_template_digest != _digest("chat-template", chat_template_wire)
            or proof.chat_template_bytes != len(chat_template_wire)
            or proof.token_sequence_digest != _digest("token-sequence", token_sequence_wire)
            or proof.token_sequence_bytes != len(token_sequence_wire)
            or proof.prompt_tokens != len(evidence.token_ids)
            or proof.total_tokens != proof.prompt_tokens + WEB_ANALYSIS_COMPLETION_TOKENS
            or proof.remaining_tokens != WEB_ANALYSIS_CONTEXT_TOKENS - proof.total_tokens
            or pin.conservative_campaign_prompt_tokens != conservative_prompt_bound
            or pin.conservative_campaign_total_tokens
            != conservative_prompt_bound + WEB_ANALYSIS_COMPLETION_TOKENS
            or pin.conservative_campaign_total_tokens > WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET
            or proof.conservative_campaign_prompt_tokens != pin.conservative_campaign_prompt_tokens
            or proof.conservative_campaign_total_tokens != pin.conservative_campaign_total_tokens
            or index.run_id != expected_run_id
            or index.projection_digest != projection_digest
            or index.pin_digest != pin.pin_digest
            or index.evidence_digest != evidence.evidence_digest
            or index.proof_digest != proof.proof_digest
            or index.model_materialization_attestation_digest != attestation.attestation_digest
            or started.payload
            != {
                "pinDigest": pin.pin_digest,
                "projectionDigest": projection_digest,
                "requestDigest": pin.chat_request_digest,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            }
            or mount_attested.payload != _model_mount_event_payload(attestation)
            or completed.payload
            != {
                "indexDigest": index.index_digest,
                "evidenceDigest": evidence.evidence_digest,
                "proofDigest": proof.proof_digest,
                "modelMaterializationAttestationDigest": attestation.attestation_digest,
                "promptTokens": proof.prompt_tokens,
                "totalTokens": proof.total_tokens,
                "remainingTokens": proof.remaining_tokens,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            }
        ):
            raise ValueError("Capacity v2 Run lineage, accounting, or audit differs")

        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            loaded,
            final,
            message="sealed capacity v2 Run changed after verification",
        )
        return VerifiedWebAnalysisCapacityV2Run(
            runId=expected_run_id,
            runPath=final.run_path,
            rootDigest=expected_root_digest,
            projectionDigest=projection_digest,
            pin=pin,
            evidence=evidence,
            proof=proof,
            index=index,
            modelMaterializationAttestationDigest=attestation.attestation_digest,
            startedEventHash=started.event_hash,
            modelMountAttestedEventHash=mount_attested.event_hash,
            completedEventHash=completed.event_hash,
        )
    except WebAnalysisCapacityError:
        raise
    except Exception as exc:
        raise WebAnalysisCapacityError(
            "Web analysis capacity v2 Run verification failed closed"
        ) from exc


__all__ = [
    "OfflineTokenizerV2Backend",
    "VerifiedWebAnalysisCapacityV2Run",
    "WebAnalysisCapacityV2Evidence",
    "WebAnalysisCapacityV2Index",
    "WebAnalysisCapacityV2Pin",
    "WebAnalysisCapacityV2Proof",
    "WebAnalysisModelMaterializationAttestation",
    "build_web_analysis_capacity_v2_pin",
    "create_web_analysis_capacity_v2_run",
    "load_verified_web_analysis_capacity_v2_run",
]
