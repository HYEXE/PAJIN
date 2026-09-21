"""Inert admission contract for one prepared compact Web-analysis request.

The planner in this module strictly reloads the sealed live preparation and
re-derives the exact compact ``system`` plus ``user`` Provider request.  It is
deliberately not an invocation runtime: it cannot resolve credentials, claim a
preparation, materialize a live model, dispatch a Provider request, contact a
target, or mint downstream authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated, Final, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_capacity import (
    WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET,
    WEB_ANALYSIS_COMPLETION_TOKENS,
    WEB_ANALYSIS_CONTEXT_TOKENS,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
    load_verified_web_analysis_capacity_v2_run,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    load_verified_compact_skill_bound_web_analysis_preparation,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillRegistryRef,
    VerifiedWebAnalysisSkillProjectionRun,
    load_verified_web_analysis_skill_projection,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

PREPARED_COMPACT_ADMISSION_API_VERSION: Final = (
    "pajin.dev/prepared-compact-skill-bound-web-analysis-admission/v1alpha1"
)
PREPARED_COMPACT_ADMISSION_STATUS: Final = "prepared-request-admitted-not-authorized-no-dispatch"
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]


class PreparedCompactSkillBoundWebAnalysisAdmissionError(ValueError):
    """Raised when a prepared compact request differs from sealed authority."""


def _digest(domain: str, value: object) -> str:
    encoded_domain = domain.encode("ascii", errors="strict")
    payload = canonical_json_bytes(
        value,
        label="prepared compact Web analysis admission identity material",
        max_bytes=_MAX_CANONICAL_BYTES,
    )
    return sha256(
        b"PAJIN-PREPARED-COMPACT-WEB-ANALYSIS-ADMISSION\0"
        + len(encoded_domain).to_bytes(4, "big")
        + encoded_domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Prepared compact admission authority markers must be literal false")
    return False


class _FrozenAdmissionModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope(_FrozenAdmissionModel):
    """Content-addressed, non-authoritative binding for a prepared request."""

    api_version: Literal[
        "pajin.dev/prepared-compact-skill-bound-web-analysis-admission/v1alpha1"
    ] = Field(alias="apiVersion")
    kind: Literal["PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope"]
    admission_id: str = Field(alias="admissionId", max_length=110)
    admission_digest: str = Field(alias="admissionDigest", max_length=64)
    status: Literal["prepared-request-admitted-not-authorized-no-dispatch"]

    preparation_run_id: str = Field(alias="preparationRunId", pattern=_RUN_ID_PATTERN)
    preparation_run_root_digest: _Sha256 = Field(alias="preparationRunRootDigest")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    preparation_index_digest: _Sha256 = Field(alias="preparationIndexDigest")
    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")

    source_run_id: str = Field(alias="sourceRunId", pattern=_RUN_ID_PATTERN)
    source_run_root_digest: _Sha256 = Field(alias="sourceRunRootDigest")
    skill_run_id: str = Field(alias="skillRunId", pattern=_RUN_ID_PATTERN)
    skill_run_root_digest: _Sha256 = Field(alias="skillRunRootDigest")
    skill_snapshot_digest: _Sha256 = Field(alias="skillSnapshotDigest")
    registry: SkillRegistryRef
    selection_policy_digest: _Sha256 = Field(alias="selectionPolicyDigest")

    capacity_run_id: str = Field(alias="capacityRunId", pattern=_RUN_ID_PATTERN)
    capacity_run_root_digest: _Sha256 = Field(alias="capacityRunRootDigest")
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    capacity_proof_digest: _Sha256 = Field(alias="capacityProofDigest")
    model_materialization_attestation_digest: _Sha256 = Field(
        alias="modelMaterializationAttestationDigest"
    )
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")

    compact_projection_digest: _Sha256 = Field(alias="compactProjectionDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    system_message_digest: _Sha256 = Field(alias="systemMessageDigest")
    user_message_digest: _Sha256 = Field(alias="userMessageDigest")
    response_schema_digest: _Sha256 = Field(alias="responseSchemaDigest")

    context_tokens: Literal[4096] = Field(alias="contextTokens")
    prompt_tokens: int = Field(alias="promptTokens", ge=1, le=4096)
    completion_tokens: Literal[1024] = Field(alias="completionTokens")
    total_tokens: int = Field(alias="totalTokens", ge=1, le=4096)
    remaining_tokens: int = Field(alias="remainingTokens", ge=0, le=4096)
    attempt: Literal[1]
    message_roles: tuple[Literal["system"], Literal["user"]] = Field(alias="messageRoles")

    tools_allowed: Literal[False] = Field(alias="toolsAllowed")
    streaming_allowed: Literal[False] = Field(alias="streamingAllowed")
    authorization_presented: Literal[False] = Field(alias="authorizationPresented")
    authorization_consumed: Literal[False] = Field(alias="authorizationConsumed")
    preparation_claimed: Literal[False] = Field(alias="preparationClaimed")
    live_model_materialization_attested: Literal[False] = Field(
        alias="liveModelMaterializationAttested"
    )
    model_invocation_authorized: Literal[False] = Field(alias="modelInvocationAuthorized")
    provider_dispatch_authorized: Literal[False] = Field(alias="providerDispatchAuthorized")
    target_request_authorized: Literal[False] = Field(alias="targetRequestAuthorized")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")
    automatic_redispatch_authorized: Literal[False] = Field(alias="automaticRedispatchAuthorized")

    @field_validator(
        "tools_allowed",
        "streaming_allowed",
        "authorization_presented",
        "authorization_consumed",
        "preparation_claimed",
        "live_model_materialization_attested",
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
        "context_tokens",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "remaining_tokens",
        "attempt",
        mode="before",
    )
    @classmethod
    def require_literal_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Prepared compact admission token values must be JSON integers")
        return value

    @field_validator("message_roles", mode="before")
    @classmethod
    def require_exact_message_roles(
        cls,
        value: object,
    ) -> tuple[Literal["system"], Literal["user"]]:
        if type(value) is list:
            roles = tuple(cast(list[object], value))
        elif type(value) is tuple:
            roles = cast(tuple[object, ...], value)
        else:
            raise ValueError("Prepared compact admission requires exact system,user roles")
        if roles != ("system", "user"):
            raise ValueError("Prepared compact admission requires exact system,user roles")
        return ("system", "user")

    @model_validator(mode="after")
    def bind_admission(self) -> Self:
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("Prepared compact admission exact token total differs")
        if self.remaining_tokens != self.context_tokens - self.total_tokens:
            raise ValueError("Prepared compact admission remaining context differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"admission_id", "admission_digest"},
        )
        digest = _digest("admission-envelope/v1", material)
        admission_id = f"prepared-compact-web-analysis:{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Prepared compact admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Prepared compact admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


@dataclass(frozen=True, slots=True)
class PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
    """Exact inert request admitted for a future, separately authorized runtime."""

    registration: ProviderRegistration
    chat: ProviderChatRequest
    admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope


def _require_anchor(value: str, *, label: str, run_id: bool = False) -> None:
    pattern = _RUN_ID_PATTERN if run_id else _SHA256_PATTERN
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{label} independent anchor is invalid")


def _response_schema_digest(chat: ProviderChatRequest) -> str:
    response_format = chat.response_format
    if response_format is None:
        raise ValueError("Prepared compact response schema is absent")
    return _digest(
        "response-schema/v1",
        response_format.json_schema.model_dump(mode="json", by_alias=True)["schema"],
    )


def _strict_reload_prerequisites(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
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
) -> tuple[
    VerifiedWebAnalysisSkillProjectionRun,
    VerifiedWebAnalysisCapacityV2Run,
    VerifiedCompactSkillBoundWebAnalysisPreparationRun,
]:
    if type(source) is not VerifiedAuthenticatedDiscoveryRun:
        raise TypeError("Prepared compact admission requires the exact verified source type")
    if type(skill_run) is not VerifiedWebAnalysisSkillProjectionRun:
        raise TypeError("Prepared compact admission requires the exact verified Skill type")
    if type(capacity_run) is not VerifiedWebAnalysisCapacityV2Run:
        raise TypeError("Prepared compact admission requires the exact verified Capacity type")
    if type(preparation_run) is not VerifiedCompactSkillBoundWebAnalysisPreparationRun:
        raise TypeError("Prepared compact admission requires the exact verified preparation type")
    current_skill = load_verified_web_analysis_skill_projection(
        skill_run.run_path,
        source=source,
        expected_run_id=expected_skill_run_id,
        expected_root_digest=expected_skill_root_digest,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        expected_registry_ref=expected_registry_ref,
        expected_policy_digest=expected_policy_digest,
    )
    if current_skill != skill_run:
        raise ValueError("Supplied Skill Run differs from strict reload")
    current_capacity = load_verified_web_analysis_capacity_v2_run(
        capacity_run.run_path,
        skill_run=current_skill,
        expected_run_id=expected_capacity_run_id,
        expected_root_digest=expected_capacity_root_digest,
        expected_pin_digest=expected_capacity_pin_digest,
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_proof_digest=expected_capacity_proof_digest,
        expected_model_materialization_attestation_digest=(
            expected_capacity_model_materialization_attestation_digest
        ),
    )
    if current_capacity != capacity_run:
        raise ValueError("Supplied Capacity v2 Run differs from strict reload")
    reloaded = load_verified_compact_skill_bound_web_analysis_preparation(
        preparation_run.run_path,
        skill_run=current_skill,
        capacity_run=current_capacity,
        expected_run_id=expected_preparation_run_id,
        expected_root_digest=expected_preparation_root_digest,
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
    if reloaded != preparation_run:
        raise ValueError("Supplied compact live preparation differs from strict reload")
    if (
        reloaded.preparation.preparation_digest != expected_preparation_digest
        or reloaded.index.index_digest != expected_preparation_index_digest
        or reloaded.live_request.request_digest != expected_live_request_digest
    ):
        raise ValueError("Compact live preparation independent digest anchors differ")
    return current_skill, current_capacity, reloaded


def plan_prepared_compact_skill_bound_web_analysis_admission(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
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
) -> PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
    """Strictly admit one exact prepared request without authorizing or dispatching it."""

    try:
        for label, value, run_id in (
            ("source Run ID", expected_source_run_id, True),
            ("source Run root", expected_source_root_digest, False),
            ("Skill Run ID", expected_skill_run_id, True),
            ("Skill Run root", expected_skill_root_digest, False),
            ("Skill selection policy", expected_policy_digest, False),
            ("Capacity Run ID", expected_capacity_run_id, True),
            ("Capacity Run root", expected_capacity_root_digest, False),
            ("Capacity Pin", expected_capacity_pin_digest, False),
            ("Capacity Proof", expected_capacity_proof_digest, False),
            (
                "Capacity model materialization attestation",
                expected_capacity_model_materialization_attestation_digest,
                False,
            ),
            ("transport Pin", expected_transport_pin_digest, False),
            ("preparation Run ID", expected_preparation_run_id, True),
            ("preparation Run root", expected_preparation_root_digest, False),
            ("preparation", expected_preparation_digest, False),
            ("preparation Index", expected_preparation_index_digest, False),
            ("live request", expected_live_request_digest, False),
        ):
            _require_anchor(value, label=label, run_id=run_id)

        skill, capacity, preparation = _strict_reload_prerequisites(
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
        projection = build_compact_skill_bound_web_analysis_projection(skill.snapshot)
        chat = ProviderChatRequest.model_validate(
            build_compact_skill_bound_web_analysis_chat_request(skill.snapshot).model_dump(
                mode="python",
                by_alias=True,
            )
        )
        registration = ProviderRegistration.model_validate(
            preparation.live_request.provider_registration.model_dump(mode="python")
        )
        proof = capacity.proof
        live_request = preparation.live_request
        message_roles = tuple(message.role.value for message in chat.messages)
        # The preparation and Capacity request digests intentionally use distinct
        # domains. Their strict loaders each bind the same canonical ``chat``;
        # only the preparation's copied Capacity digest is compared directly.
        if (
            chat != live_request.chat_request
            or registration != live_request.provider_registration
            or projection.projection_digest != live_request.compact_projection_digest
            or live_request.capacity_chat_request_digest != capacity.pin.chat_request_digest
            or live_request.capacity_compact_projection_digest
            != capacity.pin.compact_projection_digest
            or preparation.preparation.capacity_proof_digest != proof.proof_digest
            or preparation.preparation.model_materialization_attestation_digest
            != capacity.model_materialization_attestation_digest
            or capacity.pin.transport_pin_digest != expected_transport_pin_digest
            or proof.request_digest != capacity.pin.chat_request_digest
            or proof.context_tokens != WEB_ANALYSIS_CONTEXT_TOKENS
            or proof.completion_tokens != WEB_ANALYSIS_COMPLETION_TOKENS
            or proof.total_tokens > proof.context_tokens
            or proof.conservative_campaign_total_tokens > WEB_ANALYSIS_CAMPAIGN_TOKEN_BUDGET
            or proof.fits is not True
            or message_roles != (ChatRole.SYSTEM.value, ChatRole.USER.value)
            or len(chat.messages) != 2
            or chat.messages[0].content is None
            or chat.messages[1].content is None
            or chat.tools
            or chat.tool_choice != "none"
            or chat.stream is not False
            or chat.parallel_tool_calls is not False
        ):
            raise ValueError("Prepared compact request differs from Capacity or preparation")

        admission = PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(
            {
                "apiVersion": PREPARED_COMPACT_ADMISSION_API_VERSION,
                "kind": "PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope",
                "admissionId": "",
                "admissionDigest": "",
                "status": PREPARED_COMPACT_ADMISSION_STATUS,
                "preparationRunId": preparation.run_id,
                "preparationRunRootDigest": preparation.root_digest,
                "preparationDigest": preparation.preparation.preparation_digest,
                "preparationIndexDigest": preparation.index.index_digest,
                "liveRequestDigest": live_request.request_digest,
                "sourceRunId": expected_source_run_id,
                "sourceRunRootDigest": expected_source_root_digest,
                "skillRunId": expected_skill_run_id,
                "skillRunRootDigest": expected_skill_root_digest,
                "skillSnapshotDigest": skill.snapshot.snapshot_digest,
                "registry": expected_registry_ref,
                "selectionPolicyDigest": expected_policy_digest,
                "capacityRunId": expected_capacity_run_id,
                "capacityRunRootDigest": expected_capacity_root_digest,
                "capacityPinDigest": expected_capacity_pin_digest,
                "capacityProofDigest": expected_capacity_proof_digest,
                "modelMaterializationAttestationDigest": (
                    expected_capacity_model_materialization_attestation_digest
                ),
                "transportPinDigest": expected_transport_pin_digest,
                "compactProjectionDigest": projection.projection_digest,
                "providerRegistrationDigest": live_request.provider_registration_digest,
                "providerChatRequestDigest": live_request.chat_request_digest,
                "systemMessageDigest": projection.system_message_digest,
                "userMessageDigest": projection.user_message_digest,
                "responseSchemaDigest": _response_schema_digest(chat),
                "contextTokens": proof.context_tokens,
                "promptTokens": proof.prompt_tokens,
                "completionTokens": proof.completion_tokens,
                "totalTokens": proof.total_tokens,
                "remainingTokens": proof.remaining_tokens,
                "attempt": 1,
                "messageRoles": ("system", "user"),
                "toolsAllowed": False,
                "streamingAllowed": False,
                "authorizationPresented": False,
                "authorizationConsumed": False,
                "preparationClaimed": False,
                "liveModelMaterializationAttested": False,
                "modelInvocationAuthorized": False,
                "providerDispatchAuthorized": False,
                "targetRequestAuthorized": False,
                "executionAuthorized": False,
                "automaticRedispatchAuthorized": False,
            }
        )
        return PlannedPreparedCompactSkillBoundWebAnalysisAdmission(
            registration=registration,
            chat=chat,
            admission=admission,
        )
    except PreparedCompactSkillBoundWebAnalysisAdmissionError:
        raise
    except Exception as exc:
        raise PreparedCompactSkillBoundWebAnalysisAdmissionError(
            "Prepared compact Skill-bound Web analysis admission failed closed"
        ) from exc


def verify_planned_prepared_compact_skill_bound_web_analysis_admission(
    planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
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
) -> PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
    """Replan from sealed inputs and reject a substituted request or envelope."""

    try:
        if type(planned) is not PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
            raise TypeError("Prepared compact admission planned-call type differs")
        expected = plan_prepared_compact_skill_bound_web_analysis_admission(
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
        canonical_registration = ProviderRegistration.model_validate(
            planned.registration.model_dump(mode="python")
        )
        canonical_chat = ProviderChatRequest.model_validate(
            planned.chat.model_dump(mode="python", by_alias=True)
        )
        canonical_admission = PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(
            planned.admission.model_dump(mode="python", by_alias=True)
        )
        if (
            canonical_registration != planned.registration
            or canonical_chat != planned.chat
            or canonical_admission != planned.admission
            or planned != expected
        ):
            raise ValueError("Prepared compact admission plan differs")
        return expected
    except PreparedCompactSkillBoundWebAnalysisAdmissionError:
        raise
    except Exception as exc:
        raise PreparedCompactSkillBoundWebAnalysisAdmissionError(
            "Prepared compact Skill-bound Web analysis admission verification failed closed"
        ) from exc


__all__ = [
    "PREPARED_COMPACT_ADMISSION_STATUS",
    "PlannedPreparedCompactSkillBoundWebAnalysisAdmission",
    "PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope",
    "PreparedCompactSkillBoundWebAnalysisAdmissionError",
    "plan_prepared_compact_skill_bound_web_analysis_admission",
    "verify_planned_prepared_compact_skill_bound_web_analysis_admission",
]
