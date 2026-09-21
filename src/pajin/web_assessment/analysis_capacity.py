"""Exact offline tokenizer capacity proof for compact Skill-bound Web analysis.

This module is deliberately preparation-only.  It may format and tokenize the
two-message request through an isolated llama.cpp server, but it cannot invoke
the model, dispatch a Provider request, contact a target, or mint execution
authority.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, Self, cast
from uuid import uuid4

from pydantic import AnyHttpUrl, ConfigDict, Field, JsonValue, field_validator, model_validator

from pajin.benchmark.effectiveness.suite import (
    MODEL_IMAGE,
    PLATFORM_MANIFESTS,
    ModelPin,
    RuntimePin,
    model_pins,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.providers.usage import provider_model_usage_upper_bound
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_local import (
    WEB_ANALYSIS_LOCAL_DURATION_SECONDS,
    WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
    WEB_ANALYSIS_LOCAL_PROVIDER_ID,
    WEB_ANALYSIS_LOCAL_SECRET_REF,
)
from pajin.web_assessment.analysis_skill_compact import (
    COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    COMPACT_SKILL_BOUND_USER_SENTINEL,
    CompactSkillBoundWebAnalysisProjection,
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
)

WEB_ANALYSIS_CAPACITY_PIN_API_VERSION: Final = "pajin.dev/web-analysis-capacity-pin/v1alpha1"
WEB_ANALYSIS_CAPACITY_EVIDENCE_API_VERSION: Final = (
    "pajin.dev/web-analysis-capacity-evidence/v1alpha1"
)
WEB_ANALYSIS_CAPACITY_PROOF_API_VERSION: Final = "pajin.dev/web-analysis-capacity-proof/v1alpha1"
WEB_ANALYSIS_CAPACITY_INDEX_API_VERSION: Final = "pajin.dev/web-analysis-capacity-index/v1alpha1"
WEB_ANALYSIS_CAPACITY_RUN_API_VERSION: Final = (
    "pajin.dev/verified-web-analysis-capacity-run/v1alpha1"
)

WEB_ANALYSIS_CONTEXT_TOKENS: Literal[4096] = 4_096
WEB_ANALYSIS_COMPLETION_TOKENS: Literal[1024] = 1_024
WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET: Literal[65536] = 65_536
LLAMA_CPP_TOKENIZER_RUNTIME_VERSION: Literal["server-b9445"] = "server-b9445"

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
_STARTED_EVENT = "web-analysis.capacity-proof.started"
_COMPLETED_EVENT = "web-analysis.capacity-proof.completed"
_CAMPAIGN_NAME = "web-analysis-capacity-proof"
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RUN_ID_RE = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_MAX_TOKENIZER_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_PROMPT_BYTES = 4 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageID = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_LLAMA_CPP_ARGV: Final = (
    "--model",
    "/models/model.gguf",
    "--host",
    "127.0.0.1",
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
_TOKENIZER_TMPFS: Final = "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=10001,gid=10001"
_TOKENIZER_RUNTIME_USER: Final = "10001:10001"
_TOKENIZER_STAGED_MODE: Final = "0400"


class WebAnalysisCapacityError(ValueError):
    """Raised when an offline capacity proof fails closed."""


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis capacity authority markers must be literal false")
    return False


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Web analysis capacity proof markers must be literal true")
    return True


def _digest(domain: str, payload: bytes) -> str:
    encoded_domain = domain.encode("ascii", errors="strict")
    return sha256(
        b"PAJIN-WEB-ANALYSIS-CAPACITY\0"
        + len(encoded_domain).to_bytes(4, "big")
        + encoded_domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _json_wire(value: object, *, label: str, max_bytes: int) -> bytes:
    return canonical_json_bytes(value, label=label, max_bytes=max_bytes)


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


def _conservative_campaign_prompt_bound(
    request: ProviderChatRequest,
    *,
    model_id: str,
) -> int:
    registration = ProviderRegistration(
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
    bound = provider_model_usage_upper_bound(registration, request)
    if bound.completion_tokens != WEB_ANALYSIS_COMPLETION_TOKENS:
        raise WebAnalysisCapacityError("Capacity completion reservation differs")
    return bound.prompt_tokens


class _FrozenCapacityModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class _NoAuthorityModel(_FrozenCapacityModel):
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


class WebAnalysisCapacityPin(_NoAuthorityModel):
    """Exact immutable model/runtime/image/transport/Skill/source lineage."""

    api_version: Literal["pajin.dev/web-analysis-capacity-pin/v1alpha1"] = Field(
        default=WEB_ANALYSIS_CAPACITY_PIN_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisCapacityPin"] = "WebAnalysisCapacityPin"
    pin_digest: str = Field(default="", alias="pinDigest", max_length=64)
    compact_projection_digest: _Sha256 = Field(alias="compactProjectionDigest")
    chat_request_digest: _Sha256 = Field(alias="chatRequestDigest")
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    model_repository: str = Field(alias="modelRepository", min_length=1, max_length=500)
    model_revision: str = Field(alias="modelRevision", min_length=1, max_length=200)
    model_filename: str = Field(alias="modelFilename", min_length=1, max_length=500)
    model_size_bytes: int = Field(alias="modelSizeBytes", ge=1)
    model_sha256: _Sha256 = Field(alias="modelSha256")
    model_pin_digest: _Sha256 = Field(alias="modelPinDigest")
    model_image: str = Field(alias="modelImage", min_length=1, max_length=500)
    model_platform: Literal["linux/arm64", "linux/amd64"] = Field(alias="modelPlatform")
    model_platform_manifest: _ImageID = Field(alias="modelPlatformManifest")
    tokenizer_runtime: Literal["llama.cpp-server"] = Field(
        default="llama.cpp-server", alias="tokenizerRuntime"
    )
    tokenizer_runtime_version: Literal["server-b9445"] = Field(
        default=LLAMA_CPP_TOKENIZER_RUNTIME_VERSION, alias="tokenizerRuntimeVersion"
    )
    tokenizer_runtime_digest: str = Field(default="", alias="tokenizerRuntimeDigest")
    tokenizer_image: str = Field(alias="tokenizerImage", min_length=1, max_length=500)
    tokenizer_image_id: _ImageID = Field(alias="tokenizerImageId")
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    skill_run_id: str = Field(alias="skillRunId", max_length=64)
    skill_run_root_digest: _Sha256 = Field(alias="skillRunRootDigest")
    skill_projection_digest: _Sha256 = Field(alias="skillProjectionDigest")
    source_run_id: str = Field(alias="sourceRunId", max_length=64)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_digest: _Sha256 = Field(alias="sourceArtifactDigest")
    context_tokens: Literal[4096] = Field(
        default=WEB_ANALYSIS_CONTEXT_TOKENS, alias="contextTokens"
    )
    completion_tokens: Literal[1024] = Field(
        default=WEB_ANALYSIS_COMPLETION_TOKENS, alias="completionTokens"
    )
    conservative_campaign_prompt_tokens: int = Field(
        alias="conservativeCampaignPromptTokens", ge=0, le=65_536
    )
    conservative_campaign_total_tokens: int = Field(
        default=0, alias="conservativeCampaignTotalTokens", ge=0, le=65_536
    )
    apply_template_endpoint: Literal["/apply-template"] = Field(
        default="/apply-template", alias="applyTemplateEndpoint"
    )
    tokenize_endpoint: Literal["/tokenize"] = Field(default="/tokenize", alias="tokenizeEndpoint")
    props_endpoint: Literal["/props"] = Field(default="/props", alias="propsEndpoint")
    add_special: Literal[True] = Field(default=True, alias="addSpecial")
    parse_special: Literal[True] = Field(default=True, alias="parseSpecial")
    with_pieces: Literal[False] = Field(default=False, alias="withPieces")
    offline: Literal[True] = True
    tokenizer_only: Literal[True] = Field(default=True, alias="tokenizerOnly")

    @field_validator("add_special", "parse_special", "offline", "tokenizer_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator("with_pieces", mode="before")
    @classmethod
    def require_false(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_pin(self) -> Self:
        if (
            _RUN_ID_RE.fullmatch(self.source_run_id) is None
            or _RUN_ID_RE.fullmatch(self.skill_run_id) is None
        ):
            raise ValueError("Web analysis capacity source Run ID is invalid")
        if _SAFE_NAME_RE.fullmatch(self.model_id) is None:
            raise ValueError("Web analysis capacity model ID is unsafe")
        image_reference_digest = "sha256:" + self.tokenizer_image.rsplit("@sha256:", 1)[-1]
        if (
            self.model_image != MODEL_IMAGE
            or self.model_platform_manifest != PLATFORM_MANIFESTS[self.model_platform]
            or self.tokenizer_image != self.model_image
            or self.tokenizer_image_id != image_reference_digest
        ):
            raise ValueError("Web analysis tokenizer image differs from the model RuntimePin")
        registered_model = ModelPin(
            name=self.model_id,
            repository=self.model_repository,
            revision=self.model_revision,
            filename=self.model_filename,
            size_bytes=self.model_size_bytes,
            sha256=self.model_sha256,
        )
        if registered_model not in model_pins():
            raise ValueError("Web analysis capacity model is not a registered ModelPin")
        model_material = {
            "name": registered_model.name,
            "repository": registered_model.repository,
            "revision": registered_model.revision,
            "filename": registered_model.filename,
            "sizeBytes": registered_model.size_bytes,
            "sha256": registered_model.sha256,
        }
        expected_model_digest = _digest(
            "registered-model-pin",
            _json_wire(model_material, label="registered model Pin", max_bytes=64 * 1024),
        )
        if self.model_pin_digest != expected_model_digest:
            raise ValueError("Web analysis registered ModelPin digest differs")
        conservative_total = (
            self.conservative_campaign_prompt_tokens + WEB_ANALYSIS_COMPLETION_TOKENS
        )
        if conservative_total > WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET:
            raise ValueError("Conservative campaign token reservation exceeds Campaign budget")
        if self.conservative_campaign_total_tokens not in {0, conservative_total}:
            raise ValueError("Conservative campaign total token count differs")
        object.__setattr__(self, "conservative_campaign_total_tokens", conservative_total)
        runtime_material = {
            "version": LLAMA_CPP_TOKENIZER_RUNTIME_VERSION,
            "image": self.tokenizer_image,
            "imageId": self.tokenizer_image_id,
            "platform": self.model_platform,
            "platformManifest": self.model_platform_manifest,
            "contextTokens": WEB_ANALYSIS_CONTEXT_TOKENS,
            "chatTemplateMode": "legacy",
            "endpoints": ["GET /props", "POST /apply-template", "POST /tokenize"],
            "tokenize": {
                "addSpecial": True,
                "parseSpecial": True,
                "withPieces": False,
            },
            "argv": list(_LLAMA_CPP_ARGV),
            "network": "none-loopback-only-no-published-ports",
            "readOnly": True,
            "capDrop": "ALL",
            "noNewPrivileges": True,
            "user": "10001:10001",
            "cpus": 4,
            "memoryMb": 6144,
            "pids": 128,
            "tmpfs": _TOKENIZER_TMPFS,
        }
        runtime_digest = _digest(
            "tokenizer-runtime-profile",
            _json_wire(
                runtime_material,
                label="tokenizer runtime profile",
                max_bytes=64 * 1024,
            ),
        )
        if self.tokenizer_runtime_digest and self.tokenizer_runtime_digest != runtime_digest:
            raise ValueError("Web analysis tokenizer runtime profile digest differs")
        object.__setattr__(self, "tokenizer_runtime_digest", runtime_digest)
        material = self.model_dump(mode="json", by_alias=True, exclude={"pin_digest"})
        digest = _digest(
            "capacity-pin",
            _json_wire(material, label="capacity Pin", max_bytes=_ARTIFACT_LIMITS[_PIN_PATH]),
        )
        if self.pin_digest and self.pin_digest != digest:
            raise ValueError("Web analysis capacity Pin digest differs")
        object.__setattr__(self, "pin_digest", digest)
        return self


class WebAnalysisCapacityEvidence(_NoAuthorityModel):
    """Replayable raw tokenizer observations required for independent recomputation."""

    api_version: Literal["pajin.dev/web-analysis-capacity-evidence/v1alpha1"] = Field(
        default=WEB_ANALYSIS_CAPACITY_EVIDENCE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisCapacityEvidence"] = "WebAnalysisCapacityEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    formatted_prompt: str = Field(alias="formattedPrompt", min_length=1)
    chat_template: str = Field(alias="chatTemplate", min_length=1)
    token_ids: tuple[int, ...] = Field(alias="tokenIds", min_length=1, max_length=4096)

    @field_validator("token_ids", mode="before")
    @classmethod
    def freeze_token_ids(cls, value: object) -> tuple[int, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("Capacity Evidence token IDs must be an exact sequence")
        values = tuple(cast(Sequence[object], value))
        if any(type(token) is not int or token < 0 or token > 2**31 - 1 for token in values):
            raise ValueError("Capacity Evidence token IDs are invalid")
        return cast(tuple[int, ...], values)

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        if (
            len(self.formatted_prompt.encode("utf-8")) > _MAX_PROMPT_BYTES
            or len(self.chat_template.encode("utf-8")) > _MAX_PROMPT_BYTES
        ):
            raise ValueError("Capacity Evidence text exceeds its byte limit")
        material = self.model_dump(mode="json", by_alias=True, exclude={"evidence_digest"})
        digest = _digest(
            "capacity-evidence",
            _json_wire(
                material,
                label="capacity Evidence",
                max_bytes=_ARTIFACT_LIMITS[_EVIDENCE_PATH],
            ),
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("Web analysis capacity Evidence digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


class WebAnalysisCapacityProof(_NoAuthorityModel):
    """Exact tokenizer result; it is evidence, never budget or execution authority."""

    api_version: Literal["pajin.dev/web-analysis-capacity-proof/v1alpha1"] = Field(
        default=WEB_ANALYSIS_CAPACITY_PROOF_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisCapacityProof"] = "WebAnalysisCapacityProof"
    proof_digest: str = Field(default="", alias="proofDigest", max_length=64)
    pin_digest: _Sha256 = Field(alias="pinDigest")
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")
    message_digest: _Sha256 = Field(alias="messageDigest")
    message_bytes: int = Field(alias="messageBytes", ge=1, le=_MAX_PROMPT_BYTES)
    message_count: Literal[2] = Field(alias="messageCount")
    request_digest: _Sha256 = Field(alias="requestDigest")
    request_bytes: int = Field(alias="requestBytes", ge=1, le=_MAX_PROMPT_BYTES)
    formatted_prompt_digest: _Sha256 = Field(alias="formattedPromptDigest")
    formatted_prompt_bytes: int = Field(alias="formattedPromptBytes", ge=1, le=_MAX_PROMPT_BYTES)
    token_sequence_digest: _Sha256 = Field(alias="tokenSequenceDigest")
    token_sequence_bytes: int = Field(
        alias="tokenSequenceBytes", ge=2, le=_MAX_TOKENIZER_RESPONSE_BYTES
    )
    chat_template_digest: _Sha256 = Field(alias="chatTemplateDigest")
    chat_template_bytes: int = Field(alias="chatTemplateBytes", ge=1, le=_MAX_PROMPT_BYTES)
    context_tokens: Literal[4096] = Field(
        default=WEB_ANALYSIS_CONTEXT_TOKENS, alias="contextTokens"
    )
    prompt_tokens: int = Field(alias="promptTokens", ge=1, le=4_096)
    completion_tokens: Literal[1024] = Field(
        default=WEB_ANALYSIS_COMPLETION_TOKENS, alias="completionTokens"
    )
    total_tokens: int = Field(alias="totalTokens", ge=1, le=4_096)
    remaining_tokens: int = Field(alias="remainingTokens", ge=0, le=4_096)
    conservative_campaign_prompt_tokens: int = Field(
        alias="conservativeCampaignPromptTokens", ge=1, le=65_536
    )
    conservative_campaign_total_tokens: int = Field(
        alias="conservativeCampaignTotalTokens", ge=1, le=65_536
    )
    fits: Literal[True]
    system_sentinel_included: Literal[True] = Field(alias="systemSentinelIncluded")
    user_sentinel_included: Literal[True] = Field(alias="userSentinelIncluded")
    model_inference_performed: Literal[False] = Field(
        default=False, alias="modelInferencePerformed"
    )
    provider_dispatch: Literal[False] = Field(default=False, alias="providerDispatch")
    target_requests: Literal[0] = Field(default=0, alias="targetRequests")

    @field_validator("fits", "system_sentinel_included", "user_sentinel_included", mode="before")
    @classmethod
    def require_proof_true(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator("model_inference_performed", "provider_dispatch", mode="before")
    @classmethod
    def require_observation_false(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("target_requests", mode="before")
    @classmethod
    def require_zero_requests(cls, value: object) -> Literal[0]:
        if type(value) is not int or value != 0:
            raise ValueError("Web analysis capacity target request count must be exact zero")
        return 0

    @model_validator(mode="after")
    def bind_proof(self) -> Self:
        if self.total_tokens != self.prompt_tokens + WEB_ANALYSIS_COMPLETION_TOKENS:
            raise ValueError("Web analysis exact total token count differs")
        if self.remaining_tokens != WEB_ANALYSIS_CONTEXT_TOKENS - self.total_tokens:
            raise ValueError("Web analysis remaining token count differs")
        if self.total_tokens > WEB_ANALYSIS_CONTEXT_TOKENS or self.fits is not True:
            raise ValueError("Web analysis request does not fit the exact context")
        conservative_total = (
            self.conservative_campaign_prompt_tokens + WEB_ANALYSIS_COMPLETION_TOKENS
        )
        if (
            self.conservative_campaign_total_tokens != conservative_total
            or conservative_total > WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET
            or self.conservative_campaign_prompt_tokens < self.prompt_tokens
        ):
            raise ValueError("Conservative campaign reservation is not a valid upper bound")
        material = self.model_dump(mode="json", by_alias=True, exclude={"proof_digest"})
        digest = _digest(
            "capacity-proof",
            _json_wire(material, label="capacity Proof", max_bytes=_ARTIFACT_LIMITS[_PROOF_PATH]),
        )
        if self.proof_digest and self.proof_digest != digest:
            raise ValueError("Web analysis capacity Proof digest differs")
        object.__setattr__(self, "proof_digest", digest)
        return self


class WebAnalysisCapacityIndex(_NoAuthorityModel):
    api_version: Literal["pajin.dev/web-analysis-capacity-index/v1alpha1"] = Field(
        default=WEB_ANALYSIS_CAPACITY_INDEX_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisCapacityIndex"] = "WebAnalysisCapacityIndex"
    index_digest: str = Field(default="", alias="indexDigest", max_length=64)
    run_id: str = Field(alias="runId", max_length=64)
    projection_path: Literal["compact-projection.json"] = Field(
        default="compact-projection.json", alias="projectionPath"
    )
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    pin_path: Literal["capacity-pin.json"] = Field(default="capacity-pin.json", alias="pinPath")
    pin_digest: _Sha256 = Field(alias="pinDigest")
    evidence_path: Literal["capacity-evidence.json"] = Field(
        default="capacity-evidence.json", alias="evidencePath"
    )
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")
    proof_path: Literal["capacity-proof.json"] = Field(
        default="capacity-proof.json", alias="proofPath"
    )
    proof_digest: _Sha256 = Field(alias="proofDigest")
    model_inference_performed: Literal[False] = Field(
        default=False, alias="modelInferencePerformed"
    )
    provider_dispatch: Literal[False] = Field(default=False, alias="providerDispatch")
    target_requests: Literal[0] = Field(default=0, alias="targetRequests")

    @field_validator("model_inference_performed", "provider_dispatch", mode="before")
    @classmethod
    def require_no_execution(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("target_requests", mode="before")
    @classmethod
    def require_no_target_requests(cls, value: object) -> Literal[0]:
        if type(value) is not int or value != 0:
            raise ValueError("Web analysis capacity Index target requests must be zero")
        return 0

    @model_validator(mode="after")
    def bind_index(self) -> Self:
        if _RUN_ID_RE.fullmatch(self.run_id) is None:
            raise ValueError("Web analysis capacity Index Run ID is invalid")
        material = self.model_dump(mode="json", by_alias=True, exclude={"index_digest"})
        digest = _digest(
            "capacity-index",
            _json_wire(material, label="capacity Index", max_bytes=_ARTIFACT_LIMITS[_INDEX_PATH]),
        )
        if self.index_digest and self.index_digest != digest:
            raise ValueError("Web analysis capacity Index digest differs")
        object.__setattr__(self, "index_digest", digest)
        return self


class VerifiedWebAnalysisCapacityRun(_FrozenCapacityModel):
    api_version: Literal["pajin.dev/verified-web-analysis-capacity-run/v1alpha1"] = Field(
        default=WEB_ANALYSIS_CAPACITY_RUN_API_VERSION, alias="apiVersion"
    )
    kind: Literal["VerifiedWebAnalysisCapacityRun"] = "VerifiedWebAnalysisCapacityRun"
    run_id: str = Field(alias="runId", max_length=64)
    run_path: Path = Field(alias="runPath")
    root_digest: _Sha256 = Field(alias="rootDigest")
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    pin: WebAnalysisCapacityPin
    evidence: WebAnalysisCapacityEvidence
    proof: WebAnalysisCapacityProof
    index: WebAnalysisCapacityIndex
    started_event_hash: _Sha256 = Field(alias="startedEventHash")
    completed_event_hash: _Sha256 = Field(alias="completedEventHash")

    @model_validator(mode="after")
    def bind_verified_run(self) -> Self:
        if (
            self.index.run_id != self.run_id
            or self.index.projection_digest != self.projection_digest
            or self.index.pin_digest != self.pin.pin_digest
            or self.index.evidence_digest != self.evidence.evidence_digest
            or self.index.proof_digest != self.proof.proof_digest
            or self.proof.pin_digest != self.pin.pin_digest
            or self.proof.evidence_digest != self.evidence.evidence_digest
        ):
            raise ValueError("Verified capacity Run lineage differs")
        return self


class OfflineTokenizerBackend(Protocol):
    """Injectable, tokenizer-only backend.  Implementations own their cleanup."""

    def start(self, pin: WebAnalysisCapacityPin) -> None: ...

    def get_props(self) -> object: ...

    def apply_template(self, messages: Sequence[Mapping[str, JsonValue]]) -> object: ...

    def tokenize(self, formatted_prompt: str) -> object: ...

    def cleanup(self) -> None: ...

    def verify_absent(self) -> None: ...


@dataclass(frozen=True, slots=True)
class TokenizerModelMountObservation:
    """Secret-free observation of descriptor-bound Docker model materialization."""

    model_pin_digest: str
    expected_model_sha256: str
    expected_model_size_bytes: int
    staged_model_sha256: str
    staged_model_size_bytes: int
    staged_model_uid: Literal[10001]
    staged_model_gid: Literal[10001]
    staged_model_mode: Literal["0400"]
    mounted_model_sha256: str
    mounted_model_size_bytes: int
    mounted_model_uid: Literal[10001]
    mounted_model_gid: Literal[10001]
    mounted_model_mode: Literal["0400"]
    tokenizer_image_id: str
    staging_strategy: Literal["descriptor-to-docker-volume"]
    materialization_kind: Literal["docker-copy"]
    mount_type: Literal["volume"]
    mount_destination: Literal["/models"]
    mount_read_only: Literal[True]
    digest_algorithm: Literal["sha256"]
    attested_before_tokenizer_requests: Literal[True]
    runtime_user_read_verified: Literal[True]
    cleanup_required: Literal[True]


class SubprocessLlamaCppTokenizerBackend:
    """Start one pinned llama.cpp server with no network or published ports."""

    def __init__(
        self,
        *,
        model_path: Path,
        docker_binary: str = "docker",
        timeout_seconds: int = 60,
        cpus: int = 4,
        memory_mb: int = 6144,
        pids_limit: int = 128,
    ) -> None:
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 600
            or cpus != 4
            or memory_mb != 6144
            or pids_limit != 128
        ):
            raise WebAnalysisCapacityError("Offline tokenizer resource profile differs")
        self._model_path = model_path
        self._docker = docker_binary
        self._timeout = timeout_seconds
        self._cpus = cpus
        self._memory_mb = memory_mb
        self._pids_limit = pids_limit
        self._seed_lifetime_seconds = max(600, timeout_seconds * 3)
        self._owner = uuid4().hex
        self._container_name = f"pajin-tokenizer-{self._owner}"
        self._seed_container_name = f"pajin-tokenizer-seed-{self._owner}"
        self._volume_name = f"pajin-tokenizer-model-{self._owner}"
        self._container_id: str | None = None
        self._seed_container_id: str | None = None
        self._container_created = False
        self._seed_container_created = False
        self._volume_created = False
        self._image_entrypoint: str | None = None
        self._pin: WebAnalysisCapacityPin | None = None
        self._ready_props: object | None = None
        self._staged_model_sha256: str | None = None
        self._mounted_model_sha256: str | None = None
        self._model_mount_observation: TokenizerModelMountObservation | None = None

    def start(self, pin: WebAnalysisCapacityPin) -> None:
        if self._pin is not None:
            raise WebAnalysisCapacityError("Offline tokenizer backend is already started")
        canonical = WebAnalysisCapacityPin.model_validate(
            pin.model_dump(mode="json", by_alias=True)
        )
        inspected = self._run((self._docker, "image", "inspect", canonical.tokenizer_image))
        image_records = parse_strict_json_bytes(
            inspected.stdout,
            label="tokenizer image inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=32,
            max_nodes=100_000,
        )
        if (
            type(image_records) is not list
            or len(image_records) != 1
            or type(image_records[0]) is not dict
        ):
            raise WebAnalysisCapacityError("Tokenizer image inspection is invalid")
        image_record = cast(dict[str, object], image_records[0])
        repo_digests = image_record.get("RepoDigests")
        image_config = image_record.get("Config")
        if type(image_config) is not dict:
            raise WebAnalysisCapacityError("Tokenizer image config is invalid")
        entrypoint = cast(dict[str, object], image_config).get("Entrypoint")
        repository_with_tag, image_digest = canonical.tokenizer_image.rsplit("@", 1)
        expected_reference = repository_with_tag.rsplit(":", 1)[0] + "@" + image_digest
        if (
            image_record.get("Id") != canonical.tokenizer_image_id
            or type(repo_digests) is not list
            or expected_reference not in repo_digests
            or f"{image_record.get('Os')}/{image_record.get('Architecture')}"
            != canonical.model_platform
            or type(entrypoint) is not list
            or len(entrypoint) != 1
            or type(entrypoint[0]) is not str
            or not entrypoint[0].startswith("/")
        ):
            raise WebAnalysisCapacityError("Tokenizer image identity differs from the Pin")
        self._image_entrypoint = entrypoint[0]

        created_volume = self._run(
            (
                self._docker,
                "volume",
                "create",
                "--label",
                "pajin.capacity-purpose=offline-tokenizer-model",
                "--label",
                f"pajin.capacity-owner={self._owner}",
                self._volume_name,
            )
        )
        self._volume_created = True
        if created_volume.stdout.decode("utf-8", errors="strict").strip() != self._volume_name:
            raise WebAnalysisCapacityError("Offline tokenizer model volume identity is invalid")

        seed_arguments = (
            self._docker,
            "create",
            "--name",
            self._seed_container_name,
            "--pull",
            "never",
            "--platform",
            canonical.model_platform,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--label",
            "pajin.capacity-purpose=offline-tokenizer-model-seed",
            "--label",
            f"pajin.capacity-owner={self._owner}",
            "--cpus",
            str(self._cpus),
            "--memory",
            f"{self._memory_mb}m",
            "--pids-limit",
            str(self._pids_limit),
            "--mount",
            f"type=volume,src={self._volume_name},dst=/models",
            "--entrypoint",
            "/usr/bin/sleep",
            canonical.tokenizer_image,
            str(self._seed_lifetime_seconds),
        )
        seed_created = self._run(seed_arguments)
        self._seed_container_created = True
        seed_id = seed_created.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[a-f0-9]{64}", seed_id) is None:
            raise WebAnalysisCapacityError("Offline tokenizer seed container ID is invalid")
        self._seed_container_id = seed_id
        self._run((self._docker, "start", seed_id))
        self._verify_seed_topology(canonical)
        self._copy_verified_model_descriptor(canonical)
        self._run(
            (
                self._docker,
                "exec",
                "-i",
                "--user",
                "0:0",
                seed_id,
                "/usr/bin/chown",
                _TOKENIZER_RUNTIME_USER,
                "/models/model.gguf",
            )
        )
        self._run(
            (
                self._docker,
                "exec",
                "-i",
                "--user",
                _TOKENIZER_RUNTIME_USER,
                seed_id,
                "/usr/bin/chmod",
                _TOKENIZER_STAGED_MODE,
                "/models/model.gguf",
            )
        )
        staged_stat = self._run(self._model_stat_arguments(seed_id))
        staged_uid, staged_gid, staged_mode, staged_size = self._parse_model_stat(
            staged_stat.stdout,
            label="staged tokenizer model",
        )
        if staged_size != canonical.model_size_bytes:
            raise WebAnalysisCapacityError("Staged tokenizer model size differs from the Pin")
        seeded = self._run(
            (
                self._docker,
                "exec",
                "-i",
                "--user",
                _TOKENIZER_RUNTIME_USER,
                seed_id,
                "/usr/bin/sha256sum",
                "/models/model.gguf",
            )
        )
        staged_digest = self._parse_model_digest(
            seeded.stdout,
            label="staged tokenizer model",
        )
        if not hmac.compare_digest(staged_digest, canonical.model_sha256):
            raise WebAnalysisCapacityError("Staged tokenizer model SHA-256 differs from the Pin")
        self._staged_model_sha256 = staged_digest
        self._remove_container(seed_id, label="tokenizer model seed")
        self._seed_container_created = False
        self._seed_container_id = None

        arguments = (
            self._docker,
            "create",
            "--name",
            self._container_name,
            "--pull",
            "never",
            "--platform",
            canonical.model_platform,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            _TOKENIZER_RUNTIME_USER,
            "--label",
            "pajin.capacity-purpose=offline-tokenizer-only",
            "--label",
            f"pajin.capacity-owner={self._owner}",
            "--label",
            "pajin.network-topology=none-loopback-only-no-published-ports",
            "--label",
            f"pajin.image-id={canonical.tokenizer_image_id}",
            "--label",
            f"pajin.platform-manifest={canonical.model_platform_manifest}",
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
            canonical.tokenizer_image,
            *_LLAMA_CPP_ARGV,
        )
        created = self._run(arguments)
        self._container_created = True
        container_id = created.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[a-f0-9]{64}", container_id) is None:
            raise WebAnalysisCapacityError("Offline tokenizer container ID is invalid")
        self._container_id = container_id
        self._pin = canonical
        self._verify_topology(canonical)
        self._run((self._docker, "start", container_id))
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
        mounted_digest = self._parse_model_digest(
            mounted.stdout,
            label="mounted tokenizer model",
        )
        if not hmac.compare_digest(mounted_digest, canonical.model_sha256):
            raise WebAnalysisCapacityError("Mounted tokenizer model SHA-256 differs from the Pin")
        self._mounted_model_sha256 = mounted_digest
        mounted_stat = self._run(self._model_stat_arguments(container_id))
        mounted_uid, mounted_gid, mounted_mode, mounted_size = self._parse_model_stat(
            mounted_stat.stdout,
            label="mounted tokenizer model",
        )
        if mounted_size != canonical.model_size_bytes:
            raise WebAnalysisCapacityError("Mounted tokenizer model size differs from the Pin")
        self._model_mount_observation = TokenizerModelMountObservation(
            model_pin_digest=canonical.model_pin_digest,
            expected_model_sha256=canonical.model_sha256,
            expected_model_size_bytes=canonical.model_size_bytes,
            staged_model_sha256=staged_digest,
            staged_model_size_bytes=staged_size,
            staged_model_uid=staged_uid,
            staged_model_gid=staged_gid,
            staged_model_mode=staged_mode,
            mounted_model_sha256=mounted_digest,
            mounted_model_size_bytes=mounted_size,
            mounted_model_uid=mounted_uid,
            mounted_model_gid=mounted_gid,
            mounted_model_mode=mounted_mode,
            tokenizer_image_id=canonical.tokenizer_image_id,
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
        last_error: BaseException | None = None
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                self._ready_props = self._request("GET", "/props", None)
                break
            except WebAnalysisCapacityError as exc:
                last_error = exc
                time.sleep(0.25)
        if self._ready_props is None:
            raise WebAnalysisCapacityError("Offline tokenizer did not become ready") from last_error

    def _copy_verified_model_descriptor(self, pin: WebAnalysisCapacityPin) -> None:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise WebAnalysisCapacityError(
                "Offline tokenizer model staging requires POSIX no-follow descriptors"
            )
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(self._model_path, flags)
            before = os.fstat(descriptor)
            identity = self._model_descriptor_identity(before)
            if before.st_size != pin.model_size_bytes:
                raise WebAnalysisCapacityError(
                    "Tokenizer model size differs before descriptor staging"
                )
            header = os.pread(descriptor, 4, 0)
            if header != b"GGUF":
                raise WebAnalysisCapacityError("Tokenizer model GGUF header differs")
            copied = self._run_descriptor_copy(descriptor)
            if copied.returncode != 0:
                raise WebAnalysisCapacityError("Offline tokenizer model staging failed closed")
            after = os.fstat(descriptor)
            if self._model_descriptor_identity(after) != identity:
                raise WebAnalysisCapacityError(
                    "Tokenizer model descriptor identity changed during staging"
                )
        except WebAnalysisCapacityError:
            raise
        except OSError as exc:
            raise WebAnalysisCapacityError(
                "Tokenizer model descriptor could not be staged"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _model_descriptor_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        if not stat.S_ISREG(value.st_mode) or value.st_ino <= 0:
            raise WebAnalysisCapacityError("Tokenizer model descriptor is not a regular file")
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def _run_descriptor_copy(
        self,
        descriptor: int,
    ) -> subprocess.CompletedProcess[bytes]:
        arguments = (
            self._docker,
            "cp",
            "-L",
            f"/dev/fd/{descriptor}",
            f"{self._seed_container_id or self._seed_container_name}:/models/model.gguf",
        )
        try:
            result = subprocess.run(
                arguments,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=self._timeout,
                pass_fds=(descriptor,),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WebAnalysisCapacityError("Offline tokenizer model staging failed") from exc
        if (
            len(result.stdout) > _MAX_TOKENIZER_RESPONSE_BYTES
            or len(result.stderr) > _MAX_TOKENIZER_RESPONSE_BYTES
        ):
            raise WebAnalysisCapacityError("Offline tokenizer model staging failed closed")
        return result

    @staticmethod
    def _parse_model_digest(value: bytes, *, label: str) -> str:
        try:
            decoded = value.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise WebAnalysisCapacityError(f"{label} digest output is invalid") from exc
        match = re.fullmatch(r"([a-f0-9]{64})  /models/model\.gguf\n?", decoded)
        if match is None:
            raise WebAnalysisCapacityError(f"{label} digest output is invalid")
        return match.group(1)

    def _model_stat_arguments(self, container_id: str) -> tuple[str, ...]:
        return (
            self._docker,
            "exec",
            "-i",
            "--user",
            _TOKENIZER_RUNTIME_USER,
            container_id,
            "/usr/bin/stat",
            "-c",
            "%u:%g:%a:%s",
            "/models/model.gguf",
        )

    @staticmethod
    def _parse_model_stat(
        value: bytes,
        *,
        label: str,
    ) -> tuple[Literal[10001], Literal[10001], Literal["0400"], int]:
        try:
            decoded = value.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise WebAnalysisCapacityError(f"{label} metadata output is invalid") from exc
        match = re.fullmatch(r"10001:10001:400:([1-9][0-9]*)\n?", decoded)
        if match is None:
            raise WebAnalysisCapacityError(f"{label} metadata differs")
        return 10001, 10001, "0400", int(match.group(1))

    def get_props(self) -> object:
        if self._ready_props is None:
            raise WebAnalysisCapacityError("Offline tokenizer readiness evidence is absent")
        return self._ready_props

    def model_mount_observation(self) -> TokenizerModelMountObservation:
        observation = self._model_mount_observation
        if observation is None:
            raise WebAnalysisCapacityError("Tokenizer model mount attestation is absent")
        return observation

    def apply_template(self, messages: Sequence[Mapping[str, JsonValue]]) -> object:
        return self._request("POST", "/apply-template", {"messages": list(messages)})

    def tokenize(self, formatted_prompt: str) -> object:
        return self._request(
            "POST",
            "/tokenize",
            {
                "content": formatted_prompt,
                "add_special": True,
                "parse_special": True,
                "with_pieces": False,
            },
        )

    def cleanup(self) -> None:
        failures: list[BaseException] = []
        for created, identity, label in (
            (
                self._container_created,
                self._container_id or self._container_name,
                "tokenizer",
            ),
            (
                self._seed_container_created,
                self._seed_container_id or self._seed_container_name,
                "tokenizer model seed",
            ),
        ):
            if not created:
                continue
            try:
                self._remove_container(identity, label=label)
            except BaseException as exc:
                failures.append(exc)
        if self._volume_created:
            try:
                self._remove_volume()
            except BaseException as exc:
                failures.append(exc)
        self._pin = None
        self._ready_props = None
        if failures:
            raise WebAnalysisCapacityError(
                "Offline tokenizer resource cleanup failed"
            ) from failures[0]

    def verify_absent(self) -> None:
        for identity in (self._container_name, self._seed_container_name):
            result = self._run_unchecked((self._docker, "container", "inspect", identity))
            if result.returncode == 0:
                raise WebAnalysisCapacityError("Offline tokenizer container remains after cleanup")
            if not any(
                marker in result.stderr for marker in (b"No such object", b"No such container")
            ):
                raise WebAnalysisCapacityError("Offline tokenizer absence could not be verified")
        owned = self._run_unchecked(
            (
                self._docker,
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=pajin.capacity-owner={self._owner}",
            )
        )
        if owned.returncode != 0 or owned.stdout.strip():
            raise WebAnalysisCapacityError("Owned offline tokenizer resources remain")
        volume = self._run_unchecked((self._docker, "volume", "inspect", self._volume_name))
        if volume.returncode == 0:
            raise WebAnalysisCapacityError("Offline tokenizer model volume remains after cleanup")
        if not any(
            marker in volume.stderr
            for marker in (b"No such volume", b"no such volume", b"No such object")
        ):
            raise WebAnalysisCapacityError("Offline tokenizer volume absence could not be verified")
        owned_volumes = self._run_unchecked(
            (
                self._docker,
                "volume",
                "ls",
                "--quiet",
                "--filter",
                f"label=pajin.capacity-owner={self._owner}",
            )
        )
        if owned_volumes.returncode != 0 or owned_volumes.stdout.strip():
            raise WebAnalysisCapacityError("Owned offline tokenizer model volumes remain")
        self._container_id = None
        self._seed_container_id = None
        self._container_created = False
        self._seed_container_created = False
        self._volume_created = False

    def _remove_container(self, identity: str, *, label: str) -> None:
        result = self._run_unchecked((self._docker, "rm", "--force", identity))
        if result.returncode != 0 and not any(
            marker in result.stderr for marker in (b"No such object", b"No such container")
        ):
            raise WebAnalysisCapacityError(f"Offline {label} container cleanup failed")

    def _remove_volume(self) -> None:
        result = self._run_unchecked((self._docker, "volume", "rm", self._volume_name))
        if result.returncode != 0 and not any(
            marker in result.stderr
            for marker in (b"No such volume", b"no such volume", b"No such object")
        ):
            raise WebAnalysisCapacityError("Offline tokenizer model volume cleanup failed")

    def _request(self, method: Literal["GET", "POST"], endpoint: str, payload: object) -> object:
        pin = self._pin
        if pin is None:
            raise WebAnalysisCapacityError("Offline tokenizer backend is not started")
        allowed = {
            ("GET", pin.props_endpoint),
            ("POST", pin.apply_template_endpoint),
            ("POST", pin.tokenize_endpoint),
        }
        if (method, endpoint) not in allowed:
            raise WebAnalysisCapacityError("Offline tokenizer endpoint is not allowed")
        arguments = [
            self._docker,
            "exec",
            "-i",
            self._container_id or self._container_name,
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            str(self._timeout),
            "--request",
            method,
            "--header",
            "Content-Type: application/json",
        ]
        stdin: bytes | None = None
        if payload is not None:
            stdin = _json_wire(payload, label="tokenizer request", max_bytes=_MAX_PROMPT_BYTES)
            arguments.extend(("--data-binary", "@-"))
        arguments.append(f"http://127.0.0.1:8080{endpoint}")
        result = self._run(tuple(arguments), stdin=stdin)
        return parse_strict_json_bytes(
            result.stdout,
            label=f"llama.cpp {endpoint} response",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=16,
            max_nodes=100_000,
        )

    def _verify_seed_topology(self, pin: WebAnalysisCapacityPin) -> None:
        if self._seed_container_id is None:
            raise WebAnalysisCapacityError("Offline tokenizer seed identity is absent")
        result = self._run((self._docker, "container", "inspect", self._seed_container_id))
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="offline tokenizer seed inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=32,
            max_nodes=100_000,
        )
        if type(decoded) is not list or len(decoded) != 1 or type(decoded[0]) is not dict:
            raise WebAnalysisCapacityError("Offline tokenizer seed inspection is invalid")
        inspection = cast(dict[str, object], decoded[0])
        config = inspection.get("Config")
        host = inspection.get("HostConfig")
        network = inspection.get("NetworkSettings")
        state = inspection.get("State")
        mounts = inspection.get("Mounts")
        if not all(type(value) is dict for value in (config, host, network, state)):
            raise WebAnalysisCapacityError("Offline tokenizer seed topology is incomplete")
        config_values = cast(dict[str, object], config)
        host_values = cast(dict[str, object], host)
        network_values = cast(dict[str, object], network)
        state_values = cast(dict[str, object], state)
        labels = config_values.get("Labels")
        if (
            inspection.get("Id") != self._seed_container_id
            or inspection.get("Image") != pin.tokenizer_image_id
            or inspection.get("Path") != "/usr/bin/sleep"
            or inspection.get("Args") != [str(self._seed_lifetime_seconds)]
            or config_values.get("Image") != pin.tokenizer_image
            or config_values.get("User") != "0:0"
            or config_values.get("Entrypoint") != ["/usr/bin/sleep"]
            or config_values.get("Cmd") != [str(self._seed_lifetime_seconds)]
            or type(labels) is not dict
            or cast(dict[str, object], labels).get("pajin.capacity-purpose")
            != "offline-tokenizer-model-seed"
            or cast(dict[str, object], labels).get("pajin.capacity-owner") != self._owner
            or host_values.get("NetworkMode") != "none"
            or host_values.get("ReadonlyRootfs") is not True
            or host_values.get("CapDrop") != ["ALL"]
            or host_values.get("CapAdd") != ["CAP_CHOWN"]
            or type(host_values.get("SecurityOpt")) is not list
            or cast(list[object], host_values.get("SecurityOpt"))
            not in (["no-new-privileges"], ["no-new-privileges:true"])
            or host_values.get("Privileged") is not False
            or host_values.get("Devices") not in (None, [])
            or host_values.get("PidMode") not in (None, "")
            or host_values.get("UTSMode") not in (None, "")
            or host_values.get("IpcMode") not in ("", "private")
            or host_values.get("NanoCpus") != 4_000_000_000
            or host_values.get("Memory") != 6144 * 1024 * 1024
            or host_values.get("PidsLimit") != 128
            or host_values.get("PortBindings") not in (None, {})
            or network_values.get("Ports") not in (None, {})
            or state_values.get("Running") is not True
            or type(mounts) is not list
            or len(mounts) != 1
            or type(mounts[0]) is not dict
            or cast(dict[str, object], mounts[0]).get("Type") != "volume"
            or cast(dict[str, object], mounts[0]).get("Name") != self._volume_name
            or cast(dict[str, object], mounts[0]).get("Destination") != "/models"
            or cast(dict[str, object], mounts[0]).get("RW") is not True
        ):
            raise WebAnalysisCapacityError("Offline tokenizer seed topology differs from the Pin")

    def _verify_topology(self, pin: WebAnalysisCapacityPin) -> None:
        if self._container_id is None or self._image_entrypoint is None:
            raise WebAnalysisCapacityError("Offline tokenizer immutable identity is absent")
        result = self._run((self._docker, "container", "inspect", self._container_id))
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="offline tokenizer container inspection",
            max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES,
            max_depth=32,
            max_nodes=100_000,
        )
        if type(decoded) is not list or len(decoded) != 1 or type(decoded[0]) is not dict:
            raise WebAnalysisCapacityError("Offline tokenizer topology inspection is invalid")
        inspection = cast(dict[str, object], decoded[0])
        config = inspection.get("Config")
        host = inspection.get("HostConfig")
        network = inspection.get("NetworkSettings")
        if type(config) is not dict or type(host) is not dict or type(network) is not dict:
            raise WebAnalysisCapacityError("Offline tokenizer topology is incomplete")
        config_values = cast(dict[str, object], config)
        host_values = cast(dict[str, object], host)
        network_values = cast(dict[str, object], network)
        labels = config_values.get("Labels")
        mounts = inspection.get("Mounts")
        expected_command = list(_LLAMA_CPP_ARGV)
        if (
            inspection.get("Id") != self._container_id
            or inspection.get("Image") != pin.tokenizer_image_id
            or inspection.get("Path") != self._image_entrypoint
            or inspection.get("Args") != expected_command
            or config_values.get("Image") != pin.tokenizer_image
            or config_values.get("User") != "10001:10001"
            or config_values.get("Cmd") != expected_command
            or type(labels) is not dict
            or cast(dict[str, object], labels).get("pajin.capacity-purpose")
            != "offline-tokenizer-only"
            or cast(dict[str, object], labels).get("pajin.capacity-owner") != self._owner
            or cast(dict[str, object], labels).get("pajin.network-topology")
            != "none-loopback-only-no-published-ports"
            or cast(dict[str, object], labels).get("pajin.image-id") != pin.tokenizer_image_id
            or cast(dict[str, object], labels).get("pajin.platform-manifest")
            != pin.model_platform_manifest
            or host_values.get("NetworkMode") != "none"
            or host_values.get("ReadonlyRootfs") is not True
            or host_values.get("CapDrop") != ["ALL"]
            or type(host_values.get("SecurityOpt")) is not list
            or cast(list[object], host_values.get("SecurityOpt"))
            not in (["no-new-privileges"], ["no-new-privileges:true"])
            or host_values.get("Privileged") is not False
            or host_values.get("CapAdd") not in (None, [])
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
            or type(mounts) is not list
            or len(mounts) != 1
            or type(mounts[0]) is not dict
            or cast(dict[str, object], mounts[0]).get("Type") != "volume"
            or cast(dict[str, object], mounts[0]).get("Name") != self._volume_name
            or cast(dict[str, object], mounts[0]).get("Destination") != "/models"
            or cast(dict[str, object], mounts[0]).get("RW") is not False
        ):
            raise WebAnalysisCapacityError("Offline tokenizer topology differs from the Pin")

    def _run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        result = self._run_unchecked(arguments, stdin=stdin)
        if result.returncode != 0:
            raise WebAnalysisCapacityError("Offline tokenizer Docker command failed closed")
        return result

    def _run_unchecked(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            result = subprocess.run(
                arguments,
                input=stdin,
                capture_output=True,
                check=False,
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WebAnalysisCapacityError("Offline tokenizer Docker command failed") from exc
        if (
            len(result.stdout) > _MAX_TOKENIZER_RESPONSE_BYTES
            or len(result.stderr) > _MAX_TOKENIZER_RESPONSE_BYTES
        ):
            raise WebAnalysisCapacityError("Offline tokenizer Docker command failed closed")
        return result


def _canonical_projection(projection: object) -> CompactSkillBoundWebAnalysisProjection:
    if type(projection) is not CompactSkillBoundWebAnalysisProjection:
        raise WebAnalysisCapacityError("Capacity proof requires the exact compact projection")
    return CompactSkillBoundWebAnalysisProjection.model_validate(
        projection.model_dump(mode="json", by_alias=True)
    )


def _canonical_request(request: ProviderChatRequest) -> ProviderChatRequest:
    if type(request) is not ProviderChatRequest:
        raise WebAnalysisCapacityError("Capacity proof requires an exact Provider chat request")
    canonical = ProviderChatRequest.model_validate(request.model_dump(mode="json", by_alias=True))
    if (
        len(canonical.messages) != 2
        or tuple(message.role for message in canonical.messages) != (ChatRole.SYSTEM, ChatRole.USER)
        or canonical.stream is not False
        or canonical.tools
        or canonical.tool_choice != "none"
        or canonical.parallel_tool_calls not in {None, False}
        or canonical.max_completion_tokens != WEB_ANALYSIS_COMPLETION_TOKENS
    ):
        raise WebAnalysisCapacityError(
            "Capacity proof request must be exact system+user tokenizer-only input"
        )
    return canonical


def _derived_skill_inputs(
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
) -> tuple[CompactSkillBoundWebAnalysisProjection, ProviderChatRequest]:
    if type(skill_run) is not VerifiedWebAnalysisSkillProjectionRun:
        raise WebAnalysisCapacityError("Capacity proof requires an exact verified Skill Run")
    return (
        build_compact_skill_bound_web_analysis_projection(skill_run.snapshot),
        build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot),
    )


def build_web_analysis_capacity_pin(
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    projection: object,
    chat_request: ProviderChatRequest,
    *,
    runtime: RuntimePin,
    model_pin: ModelPin,
    transport_pin_digest: str,
    conservative_campaign_prompt_tokens: int,
) -> WebAnalysisCapacityPin:
    canonical_projection = _canonical_projection(projection)
    canonical_request = _canonical_request(chat_request)
    expected_projection, expected_request = _derived_skill_inputs(skill_run)
    if canonical_projection != expected_projection or canonical_request != expected_request:
        raise WebAnalysisCapacityError("Capacity inputs differ from the verified Skill snapshot")
    source = skill_run.snapshot.source_snapshot
    canonical_runtime = RuntimePin.model_validate(runtime.model_dump(mode="json", by_alias=True))
    canonical_model = ModelPin.model_validate(model_pin.model_dump(mode="json", by_alias=True))
    if canonical_model not in model_pins():
        raise WebAnalysisCapacityError("Capacity model is not a registered ModelPin")
    if (
        canonical_runtime.context_size != WEB_ANALYSIS_CONTEXT_TOKENS
        or canonical_runtime.model_cpus != 4
        or canonical_runtime.model_memory_mb != 6144
        or canonical_runtime.model_pids != 128
    ):
        raise WebAnalysisCapacityError("Capacity model RuntimePin differs")
    if conservative_campaign_prompt_tokens != _conservative_campaign_prompt_bound(
        canonical_request,
        model_id=canonical_model.name,
    ):
        raise WebAnalysisCapacityError("Capacity conservative Campaign prompt bound differs")
    projection_wire = _json_wire(
        canonical_projection.model_dump(mode="json", by_alias=True),
        label="compact projection",
        max_bytes=_ARTIFACT_LIMITS[_PROJECTION_PATH],
    )
    request_wire = _json_wire(
        canonical_request.model_dump(mode="json", by_alias=True),
        label="capacity request",
        max_bytes=_MAX_PROMPT_BYTES,
    )
    return WebAnalysisCapacityPin(
        compactProjectionDigest=_digest("compact-projection", projection_wire),
        chatRequestDigest=_digest("chat-request", request_wire),
        modelId=canonical_model.name,
        modelRepository=canonical_model.repository,
        modelRevision=canonical_model.revision,
        modelFilename=canonical_model.filename,
        modelSizeBytes=canonical_model.size_bytes,
        modelSha256=canonical_model.sha256,
        modelPinDigest=_digest(
            "registered-model-pin",
            _json_wire(
                {
                    "name": canonical_model.name,
                    "repository": canonical_model.repository,
                    "revision": canonical_model.revision,
                    "filename": canonical_model.filename,
                    "sizeBytes": canonical_model.size_bytes,
                    "sha256": canonical_model.sha256,
                },
                label="registered model Pin",
                max_bytes=64 * 1024,
            ),
        ),
        modelImage=canonical_runtime.model_image,
        modelPlatform=canonical_runtime.platform,
        modelPlatformManifest=canonical_runtime.platform_manifest,
        tokenizerImage=canonical_runtime.model_image,
        tokenizerImageId=("sha256:" + canonical_runtime.model_image.rsplit("@sha256:", 1)[-1]),
        transportPinDigest=transport_pin_digest,
        skillRunId=skill_run.verification.run_id,
        skillRunRootDigest=skill_run.verification.root_digest,
        skillProjectionDigest=skill_run.snapshot.snapshot_digest,
        sourceRunId=source.source_run_id,
        sourceRootDigest=source.source_root_digest,
        sourceArtifactDigest=source.source_index_digest,
        conservativeCampaignPromptTokens=conservative_campaign_prompt_tokens,
    )


def _strict_object(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise WebAnalysisCapacityError(f"{label} must be a strict JSON object")
    return cast(dict[str, object], value)


def _props_values(value: object) -> tuple[str, int]:
    props = _strict_object(value, label="llama.cpp props")
    template = props.get("chat_template")
    context = props.get("n_ctx")
    defaults = props.get("default_generation_settings")
    if context is None and type(defaults) is dict:
        context = cast(dict[str, object], defaults).get("n_ctx")
    if (
        type(template) is not str
        or not template
        or len(template.encode("utf-8")) > _MAX_PROMPT_BYTES
        or type(context) is not int
        or context != WEB_ANALYSIS_CONTEXT_TOKENS
    ):
        raise WebAnalysisCapacityError("llama.cpp props differ from the capacity Pin")
    return template, context


def _formatted_prompt(value: object) -> str:
    response = _strict_object(value, label="llama.cpp apply-template response")
    if set(response) != {"prompt"}:
        raise WebAnalysisCapacityError("llama.cpp apply-template response fields differ")
    prompt = response["prompt"]
    if type(prompt) is not str or not prompt or len(prompt.encode("utf-8")) > _MAX_PROMPT_BYTES:
        raise WebAnalysisCapacityError("llama.cpp formatted prompt is invalid")
    return prompt


def _token_ids(value: object) -> tuple[int, ...]:
    response = _strict_object(value, label="llama.cpp tokenize response")
    if set(response) != {"tokens"} or type(response["tokens"]) is not list:
        raise WebAnalysisCapacityError("llama.cpp tokenize response fields differ")
    raw = cast(list[object], response["tokens"])
    if not raw or len(raw) > WEB_ANALYSIS_CONTEXT_TOKENS:
        raise WebAnalysisCapacityError("llama.cpp token sequence is outside context")
    if any(type(token) is not int or token < 0 or token > 2**31 - 1 for token in raw):
        raise WebAnalysisCapacityError("llama.cpp token sequence is invalid")
    return tuple(cast(int, token) for token in raw)


def _require_sentinels(
    request: ProviderChatRequest,
    formatted_prompt: str,
    *,
    system_sentinel: str,
    user_sentinel: str,
) -> None:
    if (
        type(system_sentinel) is not str
        or type(user_sentinel) is not str
        or not 16 <= len(system_sentinel) <= 200
        or not 16 <= len(user_sentinel) <= 200
        or system_sentinel == user_sentinel
    ):
        raise WebAnalysisCapacityError("Capacity proof sentinels must be unique bounded strings")
    system_content = request.messages[0].content or ""
    user_content = request.messages[1].content or ""
    system_index = formatted_prompt.find(system_content)
    user_index = formatted_prompt.find(user_content)
    if (
        system_content.count(system_sentinel) != 1
        or user_content.count(user_sentinel) != 1
        or user_sentinel in system_content
        or system_sentinel in user_content
        or formatted_prompt.count(system_sentinel) != 1
        or formatted_prompt.count(user_sentinel) != 1
        or formatted_prompt.count(system_content) != 1
        or formatted_prompt.count(user_content) != 1
        or system_index < 0
        or user_index < 0
        or system_index >= user_index
    ):
        raise WebAnalysisCapacityError("Formatted prompt omitted or duplicated a semantic sentinel")


def _measure_capacity(
    *,
    request: ProviderChatRequest,
    pin: WebAnalysisCapacityPin,
    backend: OfflineTokenizerBackend,
    system_sentinel: str,
    user_sentinel: str,
) -> tuple[WebAnalysisCapacityEvidence, WebAnalysisCapacityProof]:
    messages_value = [
        message.model_dump(mode="json", by_alias=True, exclude_none=True)
        for message in request.messages
    ]
    messages = cast(list[Mapping[str, JsonValue]], messages_value)
    chat_template, _ = _props_values(backend.get_props())
    formatted_prompt = _formatted_prompt(backend.apply_template(messages))
    _require_sentinels(
        request,
        formatted_prompt,
        system_sentinel=system_sentinel,
        user_sentinel=user_sentinel,
    )
    tokens = _token_ids(backend.tokenize(formatted_prompt))
    prompt_tokens = len(tokens)
    total_tokens = prompt_tokens + WEB_ANALYSIS_COMPLETION_TOKENS
    if total_tokens > WEB_ANALYSIS_CONTEXT_TOKENS:
        raise WebAnalysisCapacityError("Exact tokenized request exceeds the context window")
    if pin.conservative_campaign_prompt_tokens < prompt_tokens:
        raise WebAnalysisCapacityError("Conservative campaign reservation is below exact prompt")
    message_wire = _json_wire(
        messages_value, label="capacity messages", max_bytes=_MAX_PROMPT_BYTES
    )
    request_wire = _json_wire(
        request.model_dump(mode="json", by_alias=True),
        label="capacity request",
        max_bytes=_MAX_PROMPT_BYTES,
    )
    prompt_wire = formatted_prompt.encode("utf-8")
    token_wire = _json_wire(
        list(tokens), label="token sequence", max_bytes=_MAX_TOKENIZER_RESPONSE_BYTES
    )
    template_wire = chat_template.encode("utf-8")
    evidence = WebAnalysisCapacityEvidence(
        formattedPrompt=formatted_prompt,
        chatTemplate=chat_template,
        tokenIds=tokens,
    )
    proof = WebAnalysisCapacityProof(
        pinDigest=pin.pin_digest,
        evidenceDigest=evidence.evidence_digest,
        messageDigest=_digest("messages", message_wire),
        messageBytes=len(message_wire),
        messageCount=2,
        requestDigest=_digest("chat-request", request_wire),
        requestBytes=len(request_wire),
        formattedPromptDigest=_digest("formatted-prompt", prompt_wire),
        formattedPromptBytes=len(prompt_wire),
        tokenSequenceDigest=_digest("token-sequence", token_wire),
        tokenSequenceBytes=len(token_wire),
        chatTemplateDigest=_digest("chat-template", template_wire),
        chatTemplateBytes=len(template_wire),
        promptTokens=prompt_tokens,
        totalTokens=total_tokens,
        remainingTokens=WEB_ANALYSIS_CONTEXT_TOKENS - total_tokens,
        conservativeCampaignPromptTokens=pin.conservative_campaign_prompt_tokens,
        conservativeCampaignTotalTokens=pin.conservative_campaign_total_tokens,
        fits=True,
        systemSentinelIncluded=True,
        userSentinelIncluded=True,
    )
    return evidence, proof


def create_web_analysis_capacity_run(
    output_root: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    projection: object,
    chat_request: ProviderChatRequest,
    pin: WebAnalysisCapacityPin,
    tokenizer_backend: SubprocessLlamaCppTokenizerBackend,
    system_sentinel: str = COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    user_sentinel: str = COMPACT_SKILL_BOUND_USER_SENTINEL,
) -> VerifiedWebAnalysisCapacityRun:
    """Use only the exact production tokenizer backend to mint a capacity proof."""

    if type(tokenizer_backend) is not SubprocessLlamaCppTokenizerBackend:
        raise WebAnalysisCapacityError(
            "Production capacity proof requires the exact pinned llama.cpp backend"
        )
    return _create_web_analysis_capacity_run_with_backend(
        output_root,
        skill_run=skill_run,
        projection=projection,
        chat_request=chat_request,
        pin=pin,
        tokenizer_backend=tokenizer_backend,
        system_sentinel=system_sentinel,
        user_sentinel=user_sentinel,
    )


def _create_web_analysis_capacity_run_with_backend(
    output_root: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    projection: object,
    chat_request: ProviderChatRequest,
    pin: WebAnalysisCapacityPin,
    tokenizer_backend: OfflineTokenizerBackend,
    system_sentinel: str = COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    user_sentinel: str = COMPACT_SKILL_BOUND_USER_SENTINEL,
) -> VerifiedWebAnalysisCapacityRun:
    """Internal injection seam for deterministic tests; never a production producer."""

    try:
        canonical_projection = _canonical_projection(projection)
        canonical_request = _canonical_request(chat_request)
        if (
            system_sentinel != COMPACT_SKILL_BOUND_SYSTEM_SENTINEL
            or user_sentinel != COMPACT_SKILL_BOUND_USER_SENTINEL
        ):
            raise WebAnalysisCapacityError("Capacity sentinels differ from compact code authority")
        expected_projection, expected_request = _derived_skill_inputs(skill_run)
        if canonical_projection != expected_projection or canonical_request != expected_request:
            raise WebAnalysisCapacityError(
                "Capacity inputs differ from the verified Skill snapshot"
            )
        canonical_pin = WebAnalysisCapacityPin.model_validate(
            pin.model_dump(mode="json", by_alias=True)
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
            raise WebAnalysisCapacityError("Capacity Pin differs from projection or request")
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
        evidence: WebAnalysisCapacityEvidence | None = None
        proof: WebAnalysisCapacityProof | None = None
        operation_error: BaseException | None = None
        try:
            tokenizer_backend.start(canonical_pin)
            evidence, proof = _measure_capacity(
                request=canonical_request,
                pin=canonical_pin,
                backend=tokenizer_backend,
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
                "Offline tokenizer cleanup did not prove container absence"
            ) from cleanup_errors[0]
        if operation_error is not None:
            raise WebAnalysisCapacityError(
                "Offline tokenizer capacity measurement failed"
            ) from operation_error
        assert evidence is not None and proof is not None
        store.write_json_create_only(_PROJECTION_PATH, projection_payload)
        store.write_json_create_only(
            _PIN_PATH, canonical_pin.model_dump(mode="json", by_alias=True)
        )
        store.write_json_create_only(
            _EVIDENCE_PATH, evidence.model_dump(mode="json", by_alias=True)
        )
        store.write_json_create_only(_PROOF_PATH, proof.model_dump(mode="json", by_alias=True))
        index = WebAnalysisCapacityIndex(
            runId=store.run_id,
            projectionDigest=canonical_pin.compact_projection_digest,
            pinDigest=canonical_pin.pin_digest,
            evidenceDigest=evidence.evidence_digest,
            proofDigest=proof.proof_digest,
        )
        store.write_json_create_only(_INDEX_PATH, index.model_dump(mode="json", by_alias=True))
        store.append_event(
            _COMPLETED_EVENT,
            {
                "indexDigest": index.index_digest,
                "evidenceDigest": evidence.evidence_digest,
                "proofDigest": proof.proof_digest,
                "promptTokens": proof.prompt_tokens,
                "totalTokens": proof.total_tokens,
                "remainingTokens": proof.remaining_tokens,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            },
        )
        seal = store.seal()
        return load_verified_web_analysis_capacity_run(
            store.path,
            skill_run=skill_run,
            expected_run_id=store.run_id,
            expected_root_digest=seal.root_digest,
            expected_pin_digest=canonical_pin.pin_digest,
            expected_transport_pin_digest=canonical_pin.transport_pin_digest,
        )
    except WebAnalysisCapacityError:
        raise
    except Exception as exc:
        raise WebAnalysisCapacityError("Web analysis capacity Run creation failed closed") from exc


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
        raise WebAnalysisCapacityError(f"{label} wire is not canonical Run JSON")
    return cast(dict[str, object], raw)


def load_verified_web_analysis_capacity_run(
    run_path: Path,
    *,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    expected_run_id: str,
    expected_root_digest: str,
    expected_pin_digest: str,
    expected_transport_pin_digest: str,
) -> VerifiedWebAnalysisCapacityRun:
    """Strict-reload the five-artifact sealed capacity Run from independent anchors."""

    try:
        if (
            _RUN_ID_RE.fullmatch(expected_run_id) is None
            or _SHA256_RE.fullmatch(expected_root_digest) is None
            or _SHA256_RE.fullmatch(expected_pin_digest) is None
            or _SHA256_RE.fullmatch(expected_transport_pin_digest) is None
        ):
            raise ValueError("Capacity Run independent anchor is invalid")
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        sealed_artifacts = tuple(artifact for seal in initial.seals for artifact in seal.artifacts)
        sealed_paths = {artifact.path for artifact in sealed_artifacts}
        if (
            initial.verification.root_digest != expected_root_digest
            or initial.verification.seal_count != 1
            or initial.verification.event_count != 2
            or initial.verification.artifact_count != 5
            or len(initial.seals) != 1
            or len(sealed_artifacts) != 5
            or sealed_paths != _EXPECTED_ARTIFACTS
            or any(
                artifact.media_type != "application/json"
                or not 1 <= artifact.size_bytes <= _ARTIFACT_LIMITS[artifact.path]
                for artifact in sealed_artifacts
            )
            or len(initial.events) != 2
            or tuple(event.event_type for event in initial.events)
            != (_STARTED_EVENT, _COMPLETED_EVENT)
        ):
            raise ValueError("Capacity Run sealed layout or events differ")
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=_ARTIFACT_LIMITS,
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed capacity Run changed while artifacts were loaded",
        )
        projection_raw = _load_exact_json(
            loaded, _PROJECTION_PATH, label="compact projection artifact"
        )
        projection = CompactSkillBoundWebAnalysisProjection.model_validate(projection_raw)
        if projection.model_dump(mode="json", by_alias=True) != projection_raw:
            raise ValueError("Capacity compact projection wire fields differ")
        expected_projection, expected_request = _derived_skill_inputs(skill_run)
        source = skill_run.snapshot.source_snapshot
        if projection != expected_projection:
            raise ValueError("Capacity compact projection differs from the verified Skill Run")
        projection_payload = projection.model_dump(mode="json", by_alias=True)
        projection_digest = _digest(
            "compact-projection",
            _json_wire(
                projection_payload,
                label="compact projection",
                max_bytes=_ARTIFACT_LIMITS[_PROJECTION_PATH],
            ),
        )
        expected_request_wire = _json_wire(
            expected_request.model_dump(mode="json", by_alias=True),
            label="capacity request",
            max_bytes=_MAX_PROMPT_BYTES,
        )
        expected_messages_wire = _json_wire(
            [
                message.model_dump(mode="json", by_alias=True, exclude_none=True)
                for message in expected_request.messages
            ],
            label="capacity messages",
            max_bytes=_MAX_PROMPT_BYTES,
        )
        pin_raw = _load_exact_json(loaded, _PIN_PATH, label="capacity Pin artifact")
        evidence_raw = _load_exact_json(loaded, _EVIDENCE_PATH, label="capacity Evidence artifact")
        proof_raw = _load_exact_json(loaded, _PROOF_PATH, label="capacity Proof artifact")
        index_raw = _load_exact_json(loaded, _INDEX_PATH, label="capacity Index artifact")
        pin = WebAnalysisCapacityPin.model_validate(pin_raw)
        evidence = WebAnalysisCapacityEvidence.model_validate(evidence_raw)
        proof = WebAnalysisCapacityProof.model_validate(proof_raw)
        index = WebAnalysisCapacityIndex.model_validate(index_raw)
        if (
            pin.model_dump(mode="json", by_alias=True) != pin_raw
            or evidence.model_dump(mode="json", by_alias=True) != evidence_raw
            or proof.model_dump(mode="json", by_alias=True) != proof_raw
            or index.model_dump(mode="json", by_alias=True) != index_raw
        ):
            raise ValueError("Capacity Pin, Evidence, Proof, or Index wire fields differ")
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
        started, completed = loaded.events
        if (
            pin.pin_digest != expected_pin_digest
            or pin.transport_pin_digest != expected_transport_pin_digest
            or pin.skill_run_id != skill_run.verification.run_id
            or pin.skill_run_root_digest != skill_run.verification.root_digest
            or pin.skill_projection_digest != skill_run.snapshot.snapshot_digest
            or pin.source_run_id != source.source_run_id
            or pin.source_root_digest != source.source_root_digest
            or pin.source_artifact_digest != source.source_index_digest
            or pin.chat_request_digest != _digest("chat-request", expected_request_wire)
            or projection_digest != pin.compact_projection_digest
            or proof.pin_digest != pin.pin_digest
            or proof.evidence_digest != evidence.evidence_digest
            or proof.request_digest != pin.chat_request_digest
            or proof.request_bytes != len(expected_request_wire)
            or proof.message_digest != _digest("messages", expected_messages_wire)
            or proof.message_bytes != len(expected_messages_wire)
            or proof.formatted_prompt_digest != _digest("formatted-prompt", formatted_prompt_wire)
            or proof.formatted_prompt_bytes != len(formatted_prompt_wire)
            or proof.chat_template_digest != _digest("chat-template", chat_template_wire)
            or proof.chat_template_bytes != len(chat_template_wire)
            or proof.token_sequence_digest != _digest("token-sequence", token_sequence_wire)
            or proof.token_sequence_bytes != len(token_sequence_wire)
            or proof.prompt_tokens != len(evidence.token_ids)
            or pin.conservative_campaign_prompt_tokens != conservative_prompt_bound
            or proof.conservative_campaign_prompt_tokens != pin.conservative_campaign_prompt_tokens
            or proof.conservative_campaign_total_tokens != pin.conservative_campaign_total_tokens
            or index.run_id != expected_run_id
            or index.projection_digest != projection_digest
            or index.pin_digest != pin.pin_digest
            or index.evidence_digest != evidence.evidence_digest
            or index.proof_digest != proof.proof_digest
            or started.payload
            != {
                "pinDigest": pin.pin_digest,
                "projectionDigest": projection_digest,
                "requestDigest": pin.chat_request_digest,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            }
            or completed.payload
            != {
                "indexDigest": index.index_digest,
                "evidenceDigest": evidence.evidence_digest,
                "proofDigest": proof.proof_digest,
                "promptTokens": proof.prompt_tokens,
                "totalTokens": proof.total_tokens,
                "remainingTokens": proof.remaining_tokens,
                "modelInferencePerformed": False,
                "providerDispatch": False,
                "targetRequests": 0,
            }
        ):
            raise ValueError("Capacity Run lineage or audit differs")
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            loaded,
            final,
            message="sealed capacity Run changed after verification",
        )
        return VerifiedWebAnalysisCapacityRun(
            runId=expected_run_id,
            runPath=final.run_path,
            rootDigest=expected_root_digest,
            projectionDigest=projection_digest,
            pin=pin,
            evidence=evidence,
            proof=proof,
            index=index,
            startedEventHash=started.event_hash,
            completedEventHash=completed.event_hash,
        )
    except WebAnalysisCapacityError:
        raise
    except Exception as exc:
        raise WebAnalysisCapacityError(
            "Web analysis capacity Run verification failed closed"
        ) from exc


__all__ = [
    "OfflineTokenizerBackend",
    "SubprocessLlamaCppTokenizerBackend",
    "TokenizerModelMountObservation",
    "VerifiedWebAnalysisCapacityRun",
    "WebAnalysisCapacityError",
    "WebAnalysisCapacityEvidence",
    "WebAnalysisCapacityIndex",
    "WebAnalysisCapacityPin",
    "WebAnalysisCapacityProof",
    "build_web_analysis_capacity_pin",
    "create_web_analysis_capacity_run",
    "load_verified_web_analysis_capacity_run",
]
