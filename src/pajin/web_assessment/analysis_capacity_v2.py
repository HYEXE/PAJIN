"""Attested model materialization for compact Skill-bound Web analysis.

This additive reader and producer preserve the v1 capacity wire while requiring a
descriptor-bound Docker-volume materialization attestation.  Capacity production
remains preparation-only.  The additive live materializer can start and attest the
final model-server view, but exposes no model endpoint or dispatch authority.
"""

from __future__ import annotations

import hmac
import re
import subprocess
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator

from pajin.benchmark.effectiveness.suite import ModelPin, RuntimePin
from pajin.domain.models import StrictModel
from pajin.providers.models import ProviderChatRequest
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.web_assessment.analysis_capacity import (
    _TOKENIZER_RUNTIME_USER,
    _TOKENIZER_TMPFS,
    WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET,
    WEB_ANALYSIS_COMPLETION_TOKENS,
    WEB_ANALYSIS_CONTEXT_TOKENS,
    ModelDescriptorCopyObservation,
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
LIVE_MODEL_MATERIALIZATION_ATTESTATION_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-model-materialization-attestation/v1alpha1"
)
LIVE_MODEL_PROVIDER_ROUTE_ATTESTATION_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-model-provider-route-attestation/v1alpha1"
)
LIVE_MODEL_MATERIALIZATION_CLEANUP_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-model-materialization-cleanup/v1alpha1"
)
LIVE_MODEL_CLEANUP_ONLY_RESULT_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-model-cleanup-only-result/v1alpha1"
)
LIVE_MODEL_RESOURCE_ABSENCE_PROOF_API_VERSION: Final = (
    "pajin.dev/web-analysis-live-model-resource-absence-proof/v1alpha1"
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
_DockerID = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_OwnerID = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_LIVE_MODEL_PORT: Literal[8080] = 8080
_PROVIDER_NETWORK_ALIAS: Literal["host.docker.internal"] = "host.docker.internal"
_PROVIDER_ENDPOINT: Literal["http://host.docker.internal:8080/v1/chat/completions"] = (
    "http://host.docker.internal:8080/v1/chat/completions"
)
_LIVE_RESOURCE_KINDS: Final = (
    "runtime-container",
    "seed-container",
    "model-volume",
    "network",
)
_LiveResourceKind = Literal[
    "runtime-container",
    "seed-container",
    "model-volume",
    "network",
]
_LIVE_LLAMA_CPP_ARGV_PREFIX: Final = (
    "--model",
    "/models/model.gguf",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
    "--ctx-size",
    "4096",
    "--parallel",
    "1",
    "--no-warmup",
    "--offline",
    "--no-ui",
)


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis capacity authority markers must be literal false")
    return False


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Web analysis capacity attestation markers must be literal true")
    return True


def _expected_live_resource_names(owner: str) -> tuple[str, str, str, str]:
    return (
        f"pajin-web-analysis-live-{owner}",
        f"pajin-web-analysis-live-seed-{owner}",
        f"pajin-web-analysis-live-model-{owner}",
        f"pajin-web-analysis-live-network-{owner}",
    )


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


class WebAnalysisLiveModelMaterializationAttestation(_NoAuthorityV2Model):
    """Secret-free binding from Capacity v2 to one final live model view."""

    api_version: Literal[
        "pajin.dev/web-analysis-live-model-materialization-attestation/v1alpha1"
    ] = Field(default=LIVE_MODEL_MATERIALIZATION_ATTESTATION_API_VERSION, alias="apiVersion")
    kind: Literal["WebAnalysisLiveModelMaterializationAttestation"] = (
        "WebAnalysisLiveModelMaterializationAttestation"
    )
    attestation_digest: str = Field(default="", alias="attestationDigest", max_length=64)
    capacity_run_id: Annotated[str, Field(pattern=_RUN_ID_PATTERN, max_length=64)] = Field(
        alias="capacityRunId"
    )
    capacity_root_digest: _Sha256 = Field(alias="capacityRootDigest")
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    capacity_proof_digest: _Sha256 = Field(alias="capacityProofDigest")
    capacity_materialization_attestation_digest: _Sha256 = Field(
        alias="capacityMaterializationAttestationDigest"
    )
    model_pin_digest: _Sha256 = Field(alias="modelPinDigest")
    model_sha256: _Sha256 = Field(alias="modelSha256")
    model_size_bytes: int = Field(alias="modelSizeBytes", ge=1)
    descriptor_identity_digest: _Sha256 = Field(alias="descriptorIdentityDigest")
    descriptor_identity_stable: Literal[True] = Field(alias="descriptorIdentityStable")
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
    model_image: str = Field(alias="modelImage", min_length=1, max_length=500)
    model_image_id: _ImageID = Field(alias="modelImageId")
    model_platform: Literal["linux/amd64", "linux/arm64"] = Field(alias="modelPlatform")
    model_platform_manifest: _ImageID = Field(alias="modelPlatformManifest")
    resource_owner: _OwnerID = Field(alias="resourceOwner")
    volume_name: str = Field(alias="volumeName", min_length=1, max_length=100)
    runtime_container_name: str = Field(alias="runtimeContainerName", min_length=1, max_length=100)
    runtime_container_id: _DockerID = Field(alias="runtimeContainerId")
    network_name: str = Field(alias="networkName", min_length=1, max_length=100)
    network_id: _DockerID = Field(alias="networkId")
    mount_type: Literal["volume"] = Field(alias="mountType")
    mount_destination: Literal["/models"] = Field(alias="mountDestination")
    mount_read_only: Literal[True] = Field(alias="mountReadOnly")
    runtime_user: Literal["10001:10001"] = Field(alias="runtimeUser")
    runtime_user_read_verified: Literal[True] = Field(alias="runtimeUserReadVerified")
    internal_network: Literal[True] = Field(alias="internalNetwork")
    published_ports: Literal[0] = Field(alias="publishedPorts")
    live_port: Literal[8080] = Field(alias="livePort")
    ownership_verified: Literal[True] = Field(alias="ownershipVerified")
    attested_before_model_dispatch: Literal[True] = Field(alias="attestedBeforeModelDispatch")
    cleanup_required: Literal[True] = Field(alias="cleanupRequired")
    model_dispatch_performed: Literal[False] = Field(default=False, alias="modelDispatchPerformed")
    provider_dispatch_count: Literal[0] = Field(default=0, alias="providerDispatchCount")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")

    @field_validator(
        "descriptor_identity_stable",
        "mount_read_only",
        "runtime_user_read_verified",
        "internal_network",
        "ownership_verified",
        "attested_before_model_dispatch",
        "cleanup_required",
        mode="before",
    )
    @classmethod
    def require_live_attestation_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator("model_dispatch_performed", mode="before")
    @classmethod
    def require_no_model_dispatch(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_live_materialization(self) -> Self:
        expected_suffix = self.resource_owner
        if (
            self.model_sha256 != self.staged_model_sha256
            or self.model_sha256 != self.mounted_model_sha256
            or self.model_size_bytes != self.staged_model_size_bytes
            or self.model_size_bytes != self.mounted_model_size_bytes
            or not self.volume_name.endswith(expected_suffix)
            or not self.runtime_container_name.endswith(expected_suffix)
            or not self.network_name.endswith(expected_suffix)
        ):
            raise ValueError("Live model materialization anchors differ")
        material = self.model_dump(mode="json", by_alias=True, exclude={"attestation_digest"})
        digest = _digest(
            "live-model-materialization-attestation/v1",
            _json_wire(
                material,
                label="live model materialization attestation",
                max_bytes=256 * 1024,
            ),
        )
        if self.attestation_digest and self.attestation_digest != digest:
            raise ValueError("Live model materialization attestation digest differs")
        object.__setattr__(self, "attestation_digest", digest)
        return self


class WebAnalysisLiveModelProviderRouteAttestation(_NoAuthorityV2Model):
    """Claim-bound proof of the one exact internal live-model Provider route."""

    api_version: Literal[
        "pajin.dev/web-analysis-live-model-provider-route-attestation/v1alpha1"
    ] = Field(default=LIVE_MODEL_PROVIDER_ROUTE_ATTESTATION_API_VERSION, alias="apiVersion")
    kind: Literal["WebAnalysisLiveModelProviderRouteAttestation"] = (
        "WebAnalysisLiveModelProviderRouteAttestation"
    )
    attestation_digest: str = Field(default="", alias="attestationDigest", max_length=64)
    claim_digest: _Sha256 = Field(alias="claimDigest")
    resource_owner: _OwnerID = Field(alias="resourceOwner")
    live_materialization_attestation_digest: _Sha256 = Field(
        alias="liveMaterializationAttestationDigest"
    )
    runtime_container_name: str = Field(alias="runtimeContainerName", min_length=1, max_length=100)
    runtime_container_id: _DockerID = Field(alias="runtimeContainerId")
    network_name: str = Field(alias="networkName", min_length=1, max_length=100)
    network_id: _DockerID = Field(alias="networkId")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    provider_endpoint: Literal["http://host.docker.internal:8080/v1/chat/completions"] = Field(
        alias="providerEndpoint"
    )
    provider_endpoint_scheme: Literal["http"] = Field(alias="providerEndpointScheme")
    provider_endpoint_host: Literal["host.docker.internal"] = Field(alias="providerEndpointHost")
    provider_endpoint_port: Literal[8080] = Field(alias="providerEndpointPort")
    provider_endpoint_path: Literal["/v1/chat/completions"] = Field(alias="providerEndpointPath")
    provider_network_alias: Literal["host.docker.internal"] = Field(alias="providerNetworkAlias")
    live_port: Literal[8080] = Field(alias="livePort")
    provider_alias_exact: Literal[True] = Field(alias="providerAliasExact")
    network_members_exact: Literal[True] = Field(alias="networkMembersExact")
    attested_before_provider_dispatch: Literal[True] = Field(alias="attestedBeforeProviderDispatch")
    model_dispatch_performed: Literal[False] = Field(default=False, alias="modelDispatchPerformed")
    provider_dispatch_count: Literal[0] = Field(default=0, alias="providerDispatchCount")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")

    @field_validator(
        "provider_alias_exact",
        "network_members_exact",
        "attested_before_provider_dispatch",
        mode="before",
    )
    @classmethod
    def require_route_attestation_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator("model_dispatch_performed", mode="before")
    @classmethod
    def require_no_route_dispatch(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_provider_route(self) -> Self:
        expected_names = _expected_live_resource_names(self.resource_owner)
        if (
            self.runtime_container_name != expected_names[0]
            or self.network_name != expected_names[3]
            or self.provider_endpoint != _PROVIDER_ENDPOINT
            or self.provider_endpoint_host != self.provider_network_alias
            or self.provider_endpoint_port != self.live_port
        ):
            raise ValueError("Live model Provider route anchors differ")
        material = self.model_dump(mode="json", by_alias=True, exclude={"attestation_digest"})
        digest = _digest(
            "live-model-provider-route-attestation/v1",
            _json_wire(
                material,
                label="live model Provider route attestation",
                max_bytes=128 * 1024,
            ),
        )
        if self.attestation_digest and self.attestation_digest != digest:
            raise ValueError("Live model Provider route attestation digest differs")
        object.__setattr__(self, "attestation_digest", digest)
        return self


class WebAnalysisLiveModelMaterializationCleanup(_NoAuthorityV2Model):
    """Verified absence of every resource owned by one live materialization."""

    api_version: Literal["pajin.dev/web-analysis-live-model-materialization-cleanup/v1alpha1"] = (
        Field(default=LIVE_MODEL_MATERIALIZATION_CLEANUP_API_VERSION, alias="apiVersion")
    )
    kind: Literal["WebAnalysisLiveModelMaterializationCleanup"] = (
        "WebAnalysisLiveModelMaterializationCleanup"
    )
    cleanup_digest: str = Field(default="", alias="cleanupDigest", max_length=64)
    live_attestation_digest: _Sha256 = Field(alias="liveAttestationDigest")
    resource_owner: _OwnerID = Field(alias="resourceOwner")
    volume_name: str = Field(alias="volumeName", min_length=1, max_length=100)
    runtime_container_name: str = Field(alias="runtimeContainerName", min_length=1, max_length=100)
    seed_container_name: str = Field(alias="seedContainerName", min_length=1, max_length=100)
    network_name: str = Field(alias="networkName", min_length=1, max_length=100)
    cleanup_attempted: Literal[True] = Field(alias="cleanupAttempted")
    owned_resources_removed: Literal[True] = Field(alias="ownedResourcesRemoved")
    absence_verified: Literal[True] = Field(alias="absenceVerified")
    model_dispatch_performed: Literal[False] = Field(default=False, alias="modelDispatchPerformed")
    provider_dispatch_count: Literal[0] = Field(default=0, alias="providerDispatchCount")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")

    @field_validator(
        "cleanup_attempted",
        "owned_resources_removed",
        "absence_verified",
        mode="before",
    )
    @classmethod
    def require_cleanup_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator("model_dispatch_performed", mode="before")
    @classmethod
    def require_cleanup_no_dispatch(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_cleanup(self) -> Self:
        if not all(
            name.endswith(self.resource_owner)
            for name in (
                self.volume_name,
                self.runtime_container_name,
                self.seed_container_name,
                self.network_name,
            )
        ):
            raise ValueError("Live cleanup resource ownership differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"cleanup_digest"})
        digest = _digest(
            "live-model-materialization-cleanup/v1",
            _json_wire(material, label="live model materialization cleanup", max_bytes=128 * 1024),
        )
        if self.cleanup_digest and self.cleanup_digest != digest:
            raise ValueError("Live model materialization cleanup digest differs")
        object.__setattr__(self, "cleanup_digest", digest)
        return self


class WebAnalysisLiveModelResourceAbsenceProof(_NoAuthorityV2Model):
    """Content-addressed proof that one claim owner's exact resources are absent."""

    api_version: Literal["pajin.dev/web-analysis-live-model-resource-absence-proof/v1alpha1"] = (
        Field(default=LIVE_MODEL_RESOURCE_ABSENCE_PROOF_API_VERSION, alias="apiVersion")
    )
    kind: Literal["WebAnalysisLiveModelResourceAbsenceProof"] = (
        "WebAnalysisLiveModelResourceAbsenceProof"
    )
    proof_digest: str = Field(default="", alias="proofDigest", max_length=64)
    resource_owner: _OwnerID = Field(alias="resourceOwner")
    runtime_container_name: str = Field(alias="runtimeContainerName", min_length=1, max_length=100)
    seed_container_name: str = Field(alias="seedContainerName", min_length=1, max_length=100)
    volume_name: str = Field(alias="volumeName", min_length=1, max_length=100)
    network_name: str = Field(alias="networkName", min_length=1, max_length=100)
    exact_name_absence_verified: Literal[True] = Field(alias="exactNameAbsenceVerified")
    owner_label_absence_verified: Literal[True] = Field(alias="ownerLabelAbsenceVerified")
    matching_container_count: Literal[0] = Field(alias="matchingContainerCount")
    matching_volume_count: Literal[0] = Field(alias="matchingVolumeCount")
    matching_network_count: Literal[0] = Field(alias="matchingNetworkCount")

    @field_validator(
        "exact_name_absence_verified",
        "owner_label_absence_verified",
        mode="before",
    )
    @classmethod
    def require_absence_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @model_validator(mode="after")
    def bind_absence(self) -> Self:
        if (
            self.runtime_container_name,
            self.seed_container_name,
            self.volume_name,
            self.network_name,
        ) != _expected_live_resource_names(self.resource_owner):
            raise ValueError("Live resource absence names differ from their claim owner")
        material = self.model_dump(mode="json", by_alias=True, exclude={"proof_digest"})
        digest = _digest(
            "live-model-resource-absence-proof/v1",
            _json_wire(material, label="live model resource absence proof", max_bytes=128 * 1024),
        )
        if self.proof_digest and self.proof_digest != digest:
            raise ValueError("Live model resource absence proof digest differs")
        object.__setattr__(self, "proof_digest", digest)
        return self


class WebAnalysisLiveModelCleanupOnlyResult(_NoAuthorityV2Model):
    """Cleanup-only result independent of materialization success or process lifetime."""

    api_version: Literal["pajin.dev/web-analysis-live-model-cleanup-only-result/v1alpha1"] = Field(
        default=LIVE_MODEL_CLEANUP_ONLY_RESULT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisLiveModelCleanupOnlyResult"] = "WebAnalysisLiveModelCleanupOnlyResult"
    cleanup_digest: str = Field(default="", alias="cleanupDigest", max_length=64)
    resource_owner: _OwnerID = Field(alias="resourceOwner")
    runtime_container_name: str = Field(alias="runtimeContainerName", min_length=1, max_length=100)
    seed_container_name: str = Field(alias="seedContainerName", min_length=1, max_length=100)
    volume_name: str = Field(alias="volumeName", min_length=1, max_length=100)
    network_name: str = Field(alias="networkName", min_length=1, max_length=100)
    removed_resources: tuple[_LiveResourceKind, ...] = Field(alias="removedResources")
    already_absent_resources: tuple[_LiveResourceKind, ...] = Field(alias="alreadyAbsentResources")
    present_resource_ownership_verified: Literal[True] = Field(
        alias="presentResourceOwnershipVerified"
    )
    cleanup_only: Literal[True] = Field(alias="cleanupOnly")
    absence_proof_digest: _Sha256 = Field(alias="absenceProofDigest")
    docker_create_count: Literal[0] = Field(default=0, alias="dockerCreateCount")
    docker_start_count: Literal[0] = Field(default=0, alias="dockerStartCount")
    model_dispatch_count: Literal[0] = Field(default=0, alias="modelDispatchCount")

    @field_validator(
        "present_resource_ownership_verified",
        "cleanup_only",
        mode="before",
    )
    @classmethod
    def require_cleanup_only_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @model_validator(mode="after")
    def bind_cleanup_only(self) -> Self:
        if (
            self.runtime_container_name,
            self.seed_container_name,
            self.volume_name,
            self.network_name,
        ) != _expected_live_resource_names(self.resource_owner):
            raise ValueError("Live cleanup-only names differ from their claim owner")
        removed = self.removed_resources
        absent = self.already_absent_resources
        if (
            removed != tuple(kind for kind in _LIVE_RESOURCE_KINDS if kind in removed)
            or absent != tuple(kind for kind in _LIVE_RESOURCE_KINDS if kind in absent)
            or set(removed).intersection(absent)
            or set(removed).union(absent) != set(_LIVE_RESOURCE_KINDS)
        ):
            raise ValueError("Live cleanup-only resource partition differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"cleanup_digest"})
        digest = _digest(
            "live-model-cleanup-only-result/v1",
            _json_wire(material, label="live model cleanup-only result", max_bytes=128 * 1024),
        )
        if self.cleanup_digest and self.cleanup_digest != digest:
            raise ValueError("Live model cleanup-only result digest differs")
        object.__setattr__(self, "cleanup_digest", digest)
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


class SubprocessLlamaCppLiveMaterialization(SubprocessLlamaCppTokenizerBackend):
    """Own and attest one live model server without exposing a dispatch API."""

    def __init__(
        self,
        *,
        model_path: Path,
        docker_binary: str = "docker",
        timeout_seconds: int = 60,
        cpus: int = 4,
        memory_mb: int = 6144,
        pids_limit: int = 128,
        resource_owner: str | None = None,
        provider_network_alias: Literal["host.docker.internal"] | None = None,
    ) -> None:
        if resource_owner is not None and (
            type(resource_owner) is not str or re.fullmatch(r"[a-f0-9]{32}", resource_owner) is None
        ):
            raise WebAnalysisCapacityError("Live materialization resource owner is invalid")
        super().__init__(
            model_path=model_path,
            docker_binary=docker_binary,
            timeout_seconds=timeout_seconds,
            cpus=cpus,
            memory_mb=memory_mb,
            pids_limit=pids_limit,
        )
        if resource_owner is not None:
            self._owner = resource_owner
        if provider_network_alias not in (None, _PROVIDER_NETWORK_ALIAS):
            raise WebAnalysisCapacityError("Live materialization Provider network alias is invalid")
        self._provider_network_alias = provider_network_alias
        self._container_name = f"pajin-web-analysis-live-{self._owner}"
        self._seed_container_name = f"pajin-web-analysis-live-seed-{self._owner}"
        self._volume_name = f"pajin-web-analysis-live-model-{self._owner}"
        self._network_name = f"pajin-web-analysis-live-network-{self._owner}"
        self._network_id: str | None = None
        self._network_created = False
        self._network_create_attempted = False
        self._volume_create_attempted = False
        self._seed_container_create_attempted = False
        self._live_container_create_attempted = False
        self._capacity_run: VerifiedWebAnalysisCapacityV2Run | None = None
        self._live_attestation: WebAnalysisLiveModelMaterializationAttestation | None = None
        self._cleanup_attempted = False
        self._cleanup_result: WebAnalysisLiveModelMaterializationCleanup | None = None

    def start(self, pin: WebAnalysisCapacityPin) -> None:
        del pin
        raise WebAnalysisCapacityError(
            "Live materialization requires an exact verified Capacity v2 Run"
        )

    def materialize(self, capacity_run: VerifiedWebAnalysisCapacityV2Run) -> None:
        if self._capacity_run is not None or self._live_attestation is not None:
            raise WebAnalysisCapacityError("Live model materialization is already started")
        if type(capacity_run) is not VerifiedWebAnalysisCapacityV2Run:
            raise WebAnalysisCapacityError(
                "Live materialization requires the exact Capacity v2 Run"
            )
        canonical = VerifiedWebAnalysisCapacityV2Run.model_validate(
            capacity_run.model_dump(mode="python", by_alias=True)
        )
        pin = canonical.pin
        self._image_entrypoint = self._inspect_pinned_image(pin)
        self._create_owned_internal_network()
        self._stage_descriptor_bound_model_volume(pin)
        staged = self._staged_model_volume_observation
        if staged is None:
            raise WebAnalysisCapacityError("Live staged model observation is absent")
        descriptor = staged.descriptor_copy
        if descriptor.before != descriptor.after:
            raise WebAnalysisCapacityError("Live model descriptor identity changed during copy")

        arguments = self._live_container_create_arguments(pin)
        self._live_container_create_attempted = True
        created = self._run(arguments)
        self._container_created = True
        container_id = created.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[a-f0-9]{64}", container_id) is None:
            raise WebAnalysisCapacityError("Live model container ID is invalid")
        self._container_id = container_id
        self._pin = pin
        self._run((self._docker, "start", container_id))
        self._verify_live_topology(pin)
        mounted_digest, mounted_uid, mounted_gid, mounted_mode, mounted_size = (
            self._observe_live_model(pin)
        )
        observation = TokenizerModelMountObservation(
            model_pin_digest=pin.model_pin_digest,
            expected_model_sha256=pin.model_sha256,
            expected_model_size_bytes=pin.model_size_bytes,
            staged_model_sha256=staged.model_sha256,
            staged_model_size_bytes=staged.model_size_bytes,
            staged_model_uid=staged.model_uid,
            staged_model_gid=staged.model_gid,
            staged_model_mode=staged.model_mode,
            mounted_model_sha256=mounted_digest,
            mounted_model_size_bytes=mounted_size,
            mounted_model_uid=mounted_uid,
            mounted_model_gid=mounted_gid,
            mounted_model_mode=mounted_mode,
            tokenizer_image_id=pin.tokenizer_image_id,
            staging_strategy="descriptor-to-docker-volume",
            materialization_kind="docker-copy",
            mount_type="volume",
            mount_destination="/models",
            mount_read_only=True,
            digest_algorithm="sha256",
            attested_before_tokenizer_requests=True,
            runtime_user_read_verified=True,
            cleanup_required=True,
        )
        current_capacity_attestation = _attestation_from_observation(observation, pin=pin)
        admitted_capacity_attestation = canonical.evidence.model_materialization_attestation
        if (
            current_capacity_attestation != admitted_capacity_attestation
            or current_capacity_attestation.attestation_digest
            != canonical.model_materialization_attestation_digest
        ):
            raise WebAnalysisCapacityError(
                "Live model materialization differs from the admitted Capacity v2 anchor"
            )
        self._verify_model_volume_ownership()
        self._verify_network_ownership()
        descriptor_identity_digest = _descriptor_identity_digest(descriptor)
        network_id = self._network_id
        if network_id is None:
            raise WebAnalysisCapacityError("Live model network identity is absent")
        self._capacity_run = canonical
        self._live_attestation = WebAnalysisLiveModelMaterializationAttestation(
            capacityRunId=canonical.run_id,
            capacityRootDigest=canonical.root_digest,
            capacityPinDigest=pin.pin_digest,
            capacityProofDigest=canonical.proof.proof_digest,
            capacityMaterializationAttestationDigest=(
                canonical.model_materialization_attestation_digest
            ),
            modelPinDigest=pin.model_pin_digest,
            modelSha256=pin.model_sha256,
            modelSizeBytes=pin.model_size_bytes,
            descriptorIdentityDigest=descriptor_identity_digest,
            descriptorIdentityStable=True,
            stagedModelSha256=staged.model_sha256,
            stagedModelSizeBytes=staged.model_size_bytes,
            stagedModelUid=staged.model_uid,
            stagedModelGid=staged.model_gid,
            stagedModelMode=staged.model_mode,
            mountedModelSha256=mounted_digest,
            mountedModelSizeBytes=mounted_size,
            mountedModelUid=mounted_uid,
            mountedModelGid=mounted_gid,
            mountedModelMode=mounted_mode,
            modelImage=pin.tokenizer_image,
            modelImageId=pin.tokenizer_image_id,
            modelPlatform=pin.model_platform,
            modelPlatformManifest=pin.model_platform_manifest,
            resourceOwner=self._owner,
            volumeName=self._volume_name,
            runtimeContainerName=self._container_name,
            runtimeContainerId=container_id,
            networkName=self._network_name,
            networkId=network_id,
            mountType="volume",
            mountDestination="/models",
            mountReadOnly=True,
            runtimeUser=_TOKENIZER_RUNTIME_USER,
            runtimeUserReadVerified=True,
            internalNetwork=True,
            publishedPorts=0,
            livePort=_LIVE_MODEL_PORT,
            ownershipVerified=True,
            attestedBeforeModelDispatch=True,
            cleanupRequired=True,
        )

    def live_attestation(self) -> WebAnalysisLiveModelMaterializationAttestation:
        attestation = self._live_attestation
        if attestation is None:
            raise WebAnalysisCapacityError("Live model materialization attestation is absent")
        return attestation

    def reattest_final_view(self) -> WebAnalysisLiveModelMaterializationAttestation:
        attestation = self.live_attestation()
        capacity_run = self._capacity_run
        if capacity_run is None:
            raise WebAnalysisCapacityError("Live Capacity v2 anchor is absent")
        self._verify_live_topology(capacity_run.pin)
        self._verify_model_volume_ownership()
        self._verify_network_ownership()
        digest, uid, gid, mode, size = self._observe_live_model(capacity_run.pin)
        if (
            digest != attestation.mounted_model_sha256
            or uid != attestation.mounted_model_uid
            or gid != attestation.mounted_model_gid
            or mode != attestation.mounted_model_mode
            or size != attestation.mounted_model_size_bytes
        ):
            raise WebAnalysisCapacityError("Live model final view changed after attestation")
        return attestation

    def reattest_provider_route(
        self,
        *,
        claim_digest: str,
        resource_owner: str,
        provider_registration_digest: str,
        provider_endpoint: str,
    ) -> WebAnalysisLiveModelProviderRouteAttestation:
        """Reattest and bind the exact claim-owned internal Provider route."""

        if type(claim_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", claim_digest) is None:
            raise WebAnalysisCapacityError("Live model Provider route claim digest is invalid")
        if (
            type(provider_registration_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", provider_registration_digest) is None
        ):
            raise WebAnalysisCapacityError(
                "Live model Provider route registration digest is invalid"
            )
        if type(resource_owner) is not str or resource_owner != self._owner:
            raise WebAnalysisCapacityError("Live model Provider route claim owner differs")
        if self._provider_network_alias != _PROVIDER_NETWORK_ALIAS:
            raise WebAnalysisCapacityError(
                "Live model Provider route requires the exact Provider network alias"
            )
        if type(provider_endpoint) is not str or provider_endpoint != _PROVIDER_ENDPOINT:
            raise WebAnalysisCapacityError("Live model Provider route endpoint differs")

        live_attestation = self.reattest_final_view()
        return WebAnalysisLiveModelProviderRouteAttestation(
            claimDigest=claim_digest,
            resourceOwner=resource_owner,
            liveMaterializationAttestationDigest=live_attestation.attestation_digest,
            runtimeContainerName=live_attestation.runtime_container_name,
            runtimeContainerId=live_attestation.runtime_container_id,
            networkName=live_attestation.network_name,
            networkId=live_attestation.network_id,
            providerRegistrationDigest=provider_registration_digest,
            providerEndpoint=provider_endpoint,
            providerEndpointScheme="http",
            providerEndpointHost=_PROVIDER_NETWORK_ALIAS,
            providerEndpointPort=_LIVE_MODEL_PORT,
            providerEndpointPath="/v1/chat/completions",
            providerNetworkAlias=_PROVIDER_NETWORK_ALIAS,
            livePort=_LIVE_MODEL_PORT,
            providerAliasExact=True,
            networkMembersExact=True,
            attestedBeforeProviderDispatch=True,
        )

    def cleanup_owned_resources_and_verify_absent(
        self,
    ) -> tuple[
        WebAnalysisLiveModelCleanupOnlyResult,
        WebAnalysisLiveModelResourceAbsenceProof,
    ]:
        """Recover only exact claim-owned resources, then independently prove absence."""

        self._cleanup_attempted = True
        removed: list[_LiveResourceKind] = []
        already_absent: list[_LiveResourceKind] = []
        failures: list[BaseException] = []

        container_resources: tuple[tuple[_LiveResourceKind, str, str, str], ...] = (
            (
                "runtime-container",
                self._container_name,
                "web-analysis-live-runtime",
                "live model",
            ),
            (
                "seed-container",
                self._seed_container_name,
                self._seed_container_purpose(),
                "live model seed",
            ),
        )
        for kind, name, purpose, label in container_resources:
            try:
                if self._verify_container_cleanup_owner(
                    name,
                    expected_name=name,
                    expected_purpose=purpose,
                    allow_absent=True,
                ):
                    self._remove_container(name, label=label)
                    removed.append(kind)
                else:
                    already_absent.append(kind)
            except BaseException as exc:
                failures.append(exc)

        try:
            if self._verify_model_volume_ownership(allow_absent=True):
                self._remove_volume()
                removed.append("model-volume")
            else:
                already_absent.append("model-volume")
        except BaseException as exc:
            failures.append(exc)

        try:
            if self._verify_network_ownership(allow_absent=True, expected_live_member=False):
                self._remove_network()
                removed.append("network")
            else:
                already_absent.append("network")
        except BaseException as exc:
            failures.append(exc)

        self._pin = None
        first_process_control = next(
            (failure for failure in failures if not isinstance(failure, Exception)),
            None,
        )
        if first_process_control is not None:
            for additional_failure in failures:
                if additional_failure is first_process_control:
                    continue
                # Exception annotation is best-effort and must never replace the
                # first process-control signal selected after all cleanup attempts.
                with suppress(BaseException):
                    first_process_control.add_note(
                        "Live model cleanup-only recovery also failed while preserving "
                        "process control: "
                        + audit_safe_exception_diagnostic(
                            additional_failure,
                            stage="docker-cleanup",
                        )
                    )
            raise first_process_control
        if failures:
            raise WebAnalysisCapacityError("Live model cleanup-only recovery failed") from failures[
                0
            ]

        proof = self.verify_owned_resources_absent()
        self._clear_cleanup_tracking()
        self._set_legacy_cleanup_result()
        cleanup = WebAnalysisLiveModelCleanupOnlyResult(
            resourceOwner=self._owner,
            runtimeContainerName=self._container_name,
            seedContainerName=self._seed_container_name,
            volumeName=self._volume_name,
            networkName=self._network_name,
            removedResources=tuple(removed),
            alreadyAbsentResources=tuple(already_absent),
            presentResourceOwnershipVerified=True,
            cleanupOnly=True,
            absenceProofDigest=proof.proof_digest,
        )
        return cleanup, proof

    def verify_owned_resources_absent(self) -> WebAnalysisLiveModelResourceAbsenceProof:
        """Prove exact-name and owner-label absence without trusting process-local state."""

        for identity in (self._container_name, self._seed_container_name):
            result = self._run_unchecked((self._docker, "container", "inspect", identity))
            if result.returncode == 0:
                raise WebAnalysisCapacityError("Offline tokenizer container remains after cleanup")
            if not self._resource_is_absent(
                result,
                markers=(b"No such object", b"No such container"),
            ):
                raise WebAnalysisCapacityError("Offline tokenizer absence could not be verified")
        self._require_no_owner_label_matches(
            resource="container",
            arguments=(
                self._docker,
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=pajin.capacity-owner={self._owner}",
            ),
            message="Owned offline tokenizer resources remain",
        )

        volume = self._run_unchecked((self._docker, "volume", "inspect", self._volume_name))
        if volume.returncode == 0:
            raise WebAnalysisCapacityError("Offline tokenizer model volume remains after cleanup")
        if not self._resource_is_absent(
            volume,
            markers=(b"No such volume", b"no such volume", b"No such object"),
        ):
            raise WebAnalysisCapacityError("Offline tokenizer volume absence could not be verified")
        self._require_no_owner_label_matches(
            resource="volume",
            arguments=(
                self._docker,
                "volume",
                "ls",
                "--quiet",
                "--filter",
                f"label=pajin.capacity-owner={self._owner}",
            ),
            message="Owned offline tokenizer model volumes remain",
        )

        network = self._run_unchecked((self._docker, "network", "inspect", self._network_name))
        if network.returncode == 0:
            raise WebAnalysisCapacityError("Live model network remains after cleanup")
        if not self._resource_is_absent(
            network,
            markers=(b"No such network", b"not found", b"No such object"),
        ):
            raise WebAnalysisCapacityError("Live model network absence could not be verified")
        self._require_no_owner_label_matches(
            resource="network",
            arguments=(
                self._docker,
                "network",
                "ls",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=pajin.capacity-owner={self._owner}",
            ),
            message="Owned live model networks remain",
        )
        return WebAnalysisLiveModelResourceAbsenceProof(
            resourceOwner=self._owner,
            runtimeContainerName=self._container_name,
            seedContainerName=self._seed_container_name,
            volumeName=self._volume_name,
            networkName=self._network_name,
            exactNameAbsenceVerified=True,
            ownerLabelAbsenceVerified=True,
            matchingContainerCount=0,
            matchingVolumeCount=0,
            matchingNetworkCount=0,
        )

    def get_props(self) -> object:
        raise WebAnalysisCapacityError("Live materializer exposes no model endpoints")

    def apply_template(self, messages: Sequence[Mapping[str, JsonValue]]) -> object:
        del messages
        raise WebAnalysisCapacityError("Live materializer exposes no model endpoints")

    def tokenize(self, formatted_prompt: str) -> object:
        del formatted_prompt
        raise WebAnalysisCapacityError("Live materializer exposes no model endpoints")

    def _request(
        self,
        method: Literal["GET", "POST"],
        endpoint: str,
        payload: object,
    ) -> object:
        del method, endpoint, payload
        raise WebAnalysisCapacityError("Live materializer exposes no model endpoints")

    def cleanup(self) -> None:
        self._cleanup_attempted = True
        failures: list[BaseException] = []
        if self._container_created or self._live_container_create_attempted:
            try:
                if self._verify_container_cleanup_owner(
                    self._container_id or self._container_name,
                    expected_name=self._container_name,
                    expected_purpose="web-analysis-live-runtime",
                    allow_absent=True,
                ):
                    self._remove_container(
                        self._container_id or self._container_name,
                        label="live model",
                    )
                self._container_created = False
                self._live_container_create_attempted = False
                self._container_id = None
            except BaseException as exc:
                failures.append(exc)
        if self._seed_container_created or self._seed_container_create_attempted:
            try:
                if self._verify_container_cleanup_owner(
                    self._seed_container_id or self._seed_container_name,
                    expected_name=self._seed_container_name,
                    expected_purpose=self._seed_container_purpose(),
                    allow_absent=True,
                ):
                    self._remove_container(
                        self._seed_container_id or self._seed_container_name,
                        label="live model seed",
                    )
                self._seed_container_created = False
                self._seed_container_create_attempted = False
                self._seed_container_id = None
            except BaseException as exc:
                failures.append(exc)
        if self._volume_created or self._volume_create_attempted:
            try:
                if self._verify_model_volume_ownership(allow_absent=True):
                    self._remove_volume()
                self._volume_created = False
                self._volume_create_attempted = False
            except BaseException as exc:
                failures.append(exc)
        if self._network_created or self._network_create_attempted:
            try:
                if self._verify_network_ownership(allow_absent=True):
                    self._remove_network()
                self._network_created = False
                self._network_create_attempted = False
                self._network_id = None
            except BaseException as exc:
                failures.append(exc)
        self._pin = None
        if failures:
            raise WebAnalysisCapacityError("Live model resource cleanup failed") from failures[0]

    def verify_absent(self) -> None:
        if not self._cleanup_attempted:
            raise WebAnalysisCapacityError("Live model cleanup was not attempted")
        self.verify_owned_resources_absent()
        self._clear_cleanup_tracking()
        self._set_legacy_cleanup_result()

    def cleanup_and_verify_absent(self) -> WebAnalysisLiveModelMaterializationCleanup:
        self.cleanup()
        self.verify_absent()
        return self.cleanup_result()

    def cleanup_result(self) -> WebAnalysisLiveModelMaterializationCleanup:
        result = self._cleanup_result
        if result is None:
            raise WebAnalysisCapacityError("Live model cleanup result is absent")
        return result

    def _clear_cleanup_tracking(self) -> None:
        self._container_id = None
        self._seed_container_id = None
        self._network_id = None
        self._container_created = False
        self._seed_container_created = False
        self._volume_created = False
        self._network_created = False
        self._network_create_attempted = False
        self._volume_create_attempted = False
        self._seed_container_create_attempted = False
        self._live_container_create_attempted = False

    def _set_legacy_cleanup_result(self) -> None:
        attestation = self._live_attestation
        if attestation is not None:
            self._cleanup_result = WebAnalysisLiveModelMaterializationCleanup(
                liveAttestationDigest=attestation.attestation_digest,
                resourceOwner=self._owner,
                volumeName=self._volume_name,
                runtimeContainerName=self._container_name,
                seedContainerName=self._seed_container_name,
                networkName=self._network_name,
                cleanupAttempted=True,
                ownedResourcesRemoved=True,
                absenceVerified=True,
            )

    def _require_no_owner_label_matches(
        self,
        *,
        resource: Literal["container", "volume", "network"],
        arguments: tuple[str, ...],
        message: str,
    ) -> None:
        del resource
        result = self._run_unchecked(arguments)
        if result.returncode != 0 or result.stdout.strip():
            raise WebAnalysisCapacityError(message)

    def _model_volume_purpose(self) -> str:
        return "web-analysis-live-model"

    def _seed_container_purpose(self) -> str:
        return "web-analysis-live-model-seed"

    def _after_model_volume_created(self, pin: WebAnalysisCapacityPin) -> None:
        del pin
        self._verify_model_volume_ownership()

    def _before_model_volume_create(self) -> None:
        self._volume_create_attempted = True

    def _before_seed_container_create(self) -> None:
        self._seed_container_create_attempted = True

    def _create_owned_internal_network(self) -> None:
        self._network_create_attempted = True
        created = self._run(
            (
                self._docker,
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--label",
                "pajin.capacity-purpose=web-analysis-live-network",
                "--label",
                f"pajin.capacity-owner={self._owner}",
                self._network_name,
            )
        )
        self._network_created = True
        network_id = created.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[a-f0-9]{64}", network_id) is None:
            raise WebAnalysisCapacityError("Live model network ID is invalid")
        self._network_id = network_id
        self._verify_network_ownership()

    def _live_container_create_arguments(self, pin: WebAnalysisCapacityV2Pin) -> tuple[str, ...]:
        network_alias_arguments: tuple[str, ...] = ()
        if self._provider_network_alias is not None:
            network_alias_arguments = ("--network-alias", self._provider_network_alias)
        return (
            self._docker,
            "create",
            "--name",
            self._container_name,
            "--pull",
            "never",
            "--platform",
            pin.model_platform,
            "--network",
            self._network_name,
            *network_alias_arguments,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            _TOKENIZER_RUNTIME_USER,
            "--label",
            "pajin.capacity-purpose=web-analysis-live-runtime",
            "--label",
            f"pajin.capacity-owner={self._owner}",
            "--label",
            "pajin.network-topology=owned-internal-no-published-ports",
            "--label",
            f"pajin.image-id={pin.tokenizer_image_id}",
            "--label",
            f"pajin.platform-manifest={pin.model_platform_manifest}",
            "--cpus",
            str(self._cpus),
            "--memory",
            f"{self._memory_mb}m",
            "--pids-limit",
            str(self._pids_limit),
            "--tmpfs",
            _TOKENIZER_TMPFS,
            "--mount",
            f"type=volume,src={self._volume_name},dst=/models,readonly",
            pin.tokenizer_image,
            *_LIVE_LLAMA_CPP_ARGV_PREFIX,
            "--alias",
            pin.model_id,
        )

    def _verify_model_volume_ownership(self, *, allow_absent: bool = False) -> bool:
        result = self._run_unchecked((self._docker, "volume", "inspect", self._volume_name))
        if result.returncode != 0:
            if allow_absent and self._resource_is_absent(
                result,
                markers=(b"No such volume", b"no such volume", b"No such object"),
            ):
                return False
            raise WebAnalysisCapacityError("Live model volume ownership could not be verified")
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="live model volume inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=16,
            max_nodes=10_000,
        )
        labels = {
            "pajin.capacity-purpose": self._model_volume_purpose(),
            "pajin.capacity-owner": self._owner,
        }
        if (
            type(decoded) is not list
            or len(decoded) != 1
            or type(decoded[0]) is not dict
            or decoded[0].get("Name") != self._volume_name
            or decoded[0].get("Driver") != "local"
            or decoded[0].get("Scope") != "local"
            or decoded[0].get("Labels") != labels
            or decoded[0].get("Options") not in (None, {})
        ):
            raise WebAnalysisCapacityError("Live model volume ownership differs")
        return True

    def _verify_network_ownership(
        self,
        *,
        allow_absent: bool = False,
        expected_live_member: bool | None = None,
    ) -> bool:
        network_identity = self._network_id or self._network_name
        result = self._run_unchecked((self._docker, "network", "inspect", network_identity))
        if result.returncode != 0:
            if allow_absent and self._resource_is_absent(
                result,
                markers=(b"No such network", b"not found", b"No such object"),
            ):
                return False
            raise WebAnalysisCapacityError("Live model network ownership could not be verified")
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="live model network inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=32,
            max_nodes=100_000,
        )
        labels = {
            "pajin.capacity-purpose": "web-analysis-live-network",
            "pajin.capacity-owner": self._owner,
        }
        observed_id: object = None
        members: object = None
        if type(decoded) is list and len(decoded) == 1 and type(decoded[0]) is dict:
            observed_id = decoded[0].get("Id")
            members = decoded[0].get("Containers")
        if (
            type(decoded) is not list
            or len(decoded) != 1
            or type(decoded[0]) is not dict
            or decoded[0].get("Name") != self._network_name
            or type(observed_id) is not str
            or re.fullmatch(r"[a-f0-9]{64}", observed_id) is None
            or (self._network_id is not None and observed_id != self._network_id)
            or decoded[0].get("Driver") != "bridge"
            or decoded[0].get("Internal") is not True
            or decoded[0].get("Attachable") is not False
            or decoded[0].get("Ingress") is not False
            or decoded[0].get("Labels") != labels
        ):
            raise WebAnalysisCapacityError("Live model network ownership differs")
        if expected_live_member is not None:
            container_id = self._container_id
            if expected_live_member:
                if (
                    container_id is None
                    or type(members) is not dict
                    or set(members) != {container_id}
                    or type(cast(dict[str, object], members).get(container_id)) is not dict
                    or cast(
                        dict[str, object],
                        cast(dict[str, object], members)[container_id],
                    ).get("Name")
                    != self._container_name
                ):
                    raise WebAnalysisCapacityError("Live model network member set differs")
            elif members not in (None, {}):
                raise WebAnalysisCapacityError("Live model network has unexpected members")
        self._network_id = observed_id
        return True

    def _verify_live_topology(self, pin: WebAnalysisCapacityV2Pin) -> None:
        container_id = self._container_id
        network_id = self._network_id
        if container_id is None or network_id is None or self._image_entrypoint is None:
            raise WebAnalysisCapacityError("Live model immutable identity is absent")
        result = self._run((self._docker, "container", "inspect", container_id))
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="live model container inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=32,
            max_nodes=100_000,
        )
        if type(decoded) is not list or len(decoded) != 1 or type(decoded[0]) is not dict:
            raise WebAnalysisCapacityError("Live model topology inspection is invalid")
        inspection = cast(dict[str, object], decoded[0])
        config = inspection.get("Config")
        host = inspection.get("HostConfig")
        network = inspection.get("NetworkSettings")
        state = inspection.get("State")
        mounts = inspection.get("Mounts")
        if not all(type(value) is dict for value in (config, host, network, state)):
            raise WebAnalysisCapacityError("Live model topology is incomplete")
        config_values = cast(dict[str, object], config)
        host_values = cast(dict[str, object], host)
        network_values = cast(dict[str, object], network)
        state_values = cast(dict[str, object], state)
        labels = config_values.get("Labels")
        networks = network_values.get("Networks")
        expected_command = [*_LIVE_LLAMA_CPP_ARGV_PREFIX, "--alias", pin.model_id]
        endpoint = None
        if type(networks) is dict:
            endpoint = cast(dict[str, object], networks).get(self._network_name)
        endpoint_aliases: object = None
        if type(endpoint) is dict:
            endpoint_aliases = cast(dict[str, object], endpoint).get("Aliases")
        if (
            inspection.get("Id") != container_id
            or inspection.get("Image") != pin.tokenizer_image_id
            or inspection.get("Path") != self._image_entrypoint
            or inspection.get("Args") != expected_command
            or config_values.get("Image") != pin.tokenizer_image
            or config_values.get("User") != _TOKENIZER_RUNTIME_USER
            or config_values.get("Cmd") != expected_command
            or type(labels) is not dict
            or cast(dict[str, object], labels).get("pajin.capacity-purpose")
            != "web-analysis-live-runtime"
            or cast(dict[str, object], labels).get("pajin.capacity-owner") != self._owner
            or cast(dict[str, object], labels).get("pajin.network-topology")
            != "owned-internal-no-published-ports"
            or cast(dict[str, object], labels).get("pajin.image-id") != pin.tokenizer_image_id
            or cast(dict[str, object], labels).get("pajin.platform-manifest")
            != pin.model_platform_manifest
            or host_values.get("NetworkMode") != self._network_name
            or host_values.get("ReadonlyRootfs") is not True
            or host_values.get("CapDrop") != ["ALL"]
            or host_values.get("CapAdd") not in (None, [])
            or type(host_values.get("SecurityOpt")) is not list
            or cast(list[object], host_values.get("SecurityOpt"))
            not in (["no-new-privileges"], ["no-new-privileges:true"])
            or host_values.get("Privileged") is not False
            or host_values.get("Binds") not in (None, [])
            or host_values.get("Devices") not in (None, [])
            or host_values.get("PidMode") not in (None, "")
            or host_values.get("UTSMode") not in (None, "")
            or host_values.get("IpcMode") not in ("", "private")
            or host_values.get("NanoCpus") != 4_000_000_000
            or host_values.get("Memory") != 6144 * 1024 * 1024
            or host_values.get("PidsLimit") != 128
            or host_values.get("Tmpfs")
            != {_TOKENIZER_TMPFS.split(":", 1)[0]: _TOKENIZER_TMPFS.split(":", 1)[1]}
            or host_values.get("PortBindings") not in (None, {})
            or network_values.get("Ports") not in (None, {})
            or type(networks) is not dict
            or set(cast(dict[str, object], networks)) != {self._network_name}
            or type(endpoint) is not dict
            or cast(dict[str, object], endpoint).get("NetworkID") != network_id
            or not cast(dict[str, object], endpoint).get("IPAddress")
            or not self._network_aliases_match(endpoint_aliases, container_id=container_id)
            or state_values.get("Running") is not True
            or type(mounts) is not list
            or len(mounts) != 1
            or type(mounts[0]) is not dict
            or cast(dict[str, object], mounts[0]).get("Type") != "volume"
            or cast(dict[str, object], mounts[0]).get("Name") != self._volume_name
            or cast(dict[str, object], mounts[0]).get("Destination") != "/models"
            or cast(dict[str, object], mounts[0]).get("RW") is not False
        ):
            raise WebAnalysisCapacityError("Live model topology differs from the Capacity Pin")
        self._verify_network_ownership(expected_live_member=True)

    def _network_aliases_match(self, aliases: object, *, container_id: str) -> bool:
        expected = self._provider_network_alias
        if aliases is None:
            return expected is None
        if type(aliases) is not list or any(type(alias) is not str for alias in aliases):
            return False
        observed = cast(list[str], aliases)
        allowed = {
            self._container_name,
            container_id,
            container_id[:12],
        }
        if expected is None:
            return set(observed).issubset(allowed)
        allowed.add(expected)
        return expected in observed and set(observed).issubset(allowed)

    def _observe_live_model(
        self,
        pin: WebAnalysisCapacityV2Pin,
    ) -> tuple[str, Literal[10001], Literal[10001], Literal["0400"], int]:
        container_id = self._container_id
        if container_id is None:
            raise WebAnalysisCapacityError("Live model container identity is absent")
        mounted = self._run(
            (
                self._docker,
                "exec",
                "-i",
                "--user",
                _TOKENIZER_RUNTIME_USER,
                container_id,
                "/usr/bin/sha256sum",
                "/models/model.gguf",
            )
        )
        digest = self._parse_model_digest(mounted.stdout, label="live mounted model")
        if not hmac.compare_digest(digest, pin.model_sha256):
            raise WebAnalysisCapacityError("Live mounted model SHA-256 differs from the Pin")
        mounted_stat = self._run(self._model_stat_arguments(container_id))
        uid, gid, mode, size = self._parse_model_stat(
            mounted_stat.stdout,
            label="live mounted model",
        )
        if size != pin.model_size_bytes:
            raise WebAnalysisCapacityError("Live mounted model size differs from the Pin")
        return digest, uid, gid, mode, size

    def _verify_container_cleanup_owner(
        self,
        identity: str,
        *,
        expected_name: str,
        expected_purpose: str,
        allow_absent: bool,
    ) -> bool:
        result = self._run_unchecked((self._docker, "container", "inspect", identity))
        if result.returncode != 0:
            if allow_absent and self._resource_is_absent(
                result,
                markers=(b"No such object", b"No such container"),
            ):
                return False
            raise WebAnalysisCapacityError("Live cleanup container ownership is unavailable")
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="live cleanup container inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=16,
            max_nodes=10_000,
        )
        if (
            type(decoded) is not list
            or len(decoded) != 1
            or type(decoded[0]) is not dict
            or type(decoded[0].get("Config")) is not dict
        ):
            raise WebAnalysisCapacityError("Live cleanup container ownership is invalid")
        labels = cast(dict[str, object], decoded[0]["Config"]).get("Labels")
        observed_name = decoded[0].get("Name")
        if (
            observed_name not in (expected_name, f"/{expected_name}")
            or type(labels) is not dict
            or cast(dict[str, object], labels).get("pajin.capacity-owner") != self._owner
            or cast(dict[str, object], labels).get("pajin.capacity-purpose") != expected_purpose
        ):
            raise WebAnalysisCapacityError("Live cleanup container ownership differs")
        return True

    @staticmethod
    def _resource_is_absent(
        result: subprocess.CompletedProcess[bytes],
        *,
        markers: tuple[bytes, ...],
    ) -> bool:
        return result.returncode != 0 and any(marker in result.stderr for marker in markers)

    def _remove_network(self) -> None:
        result = self._run_unchecked((self._docker, "network", "rm", self._network_name))
        if result.returncode != 0 and not any(
            marker in result.stderr
            for marker in (b"No such network", b"not found", b"No such object")
        ):
            raise WebAnalysisCapacityError("Live model network cleanup failed")
        self._network_created = False


def _descriptor_identity_digest(observation: ModelDescriptorCopyObservation) -> str:
    before = observation.before
    after = observation.after
    if before != after:
        raise WebAnalysisCapacityError("Model descriptor identity changed during live copy")
    material = {
        "device": before.device,
        "inode": before.inode,
        "sizeBytes": before.size_bytes,
        "modifiedTimeNs": before.modified_time_ns,
        "changedTimeNs": before.changed_time_ns,
    }
    return _digest(
        "live-model-descriptor-identity/v1",
        _json_wire(material, label="live model descriptor identity", max_bytes=16 * 1024),
    )


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
    "SubprocessLlamaCppLiveMaterialization",
    "VerifiedWebAnalysisCapacityV2Run",
    "WebAnalysisCapacityV2Evidence",
    "WebAnalysisCapacityV2Index",
    "WebAnalysisCapacityV2Pin",
    "WebAnalysisCapacityV2Proof",
    "WebAnalysisLiveModelCleanupOnlyResult",
    "WebAnalysisLiveModelMaterializationAttestation",
    "WebAnalysisLiveModelMaterializationCleanup",
    "WebAnalysisLiveModelProviderRouteAttestation",
    "WebAnalysisLiveModelResourceAbsenceProof",
    "WebAnalysisModelMaterializationAttestation",
    "build_web_analysis_capacity_v2_pin",
    "create_web_analysis_capacity_v2_run",
    "load_verified_web_analysis_capacity_v2_run",
]
