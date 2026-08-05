"""Content-addressed, non-invocable Supervisor model binding for SUP-001."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import CollaborationSnapshot
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.walking_shadow import (
    RegisteredWalkingShadowPolicy,
    WalkingShadowInputSnapshot,
    walking_shadow_supervisor_policy,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.domain.orchestration import AgentRole
from pajin.providers.models import ProviderRegistration
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.workflow.common_engine import registered_common_campaign_engine_contract
from pajin.workflow.profile_compatibility import (
    LegacyCampaignProfileCompilationAuthority,
    compile_legacy_campaign_profile,
)

SUPERVISOR_MODEL_BINDING_API_VERSION: Literal[
    "pajin.dev/supervisor-model-binding/v1alpha1"
] = "pajin.dev/supervisor-model-binding/v1alpha1"
SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION: Literal[
    "pajin.dev/supervisor-shadow-proposal-draft/v1alpha1"
] = "pajin.dev/supervisor-shadow-proposal-draft/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_SCHEMA_BYTES = 1024 * 1024
_MAX_COMPONENT_BYTES = 256 * 1024
_MAX_BINDING_BYTES = 4 * 1024 * 1024
_MAX_DRAFT_BYTES = 1_000_000


class SupervisorModelBindingError(RuntimeError):
    """Raised when a Supervisor model binding differs from runtime authority."""


class SupervisorShadowProposalKind(StrEnum):
    """Untrusted proposal categories; SUP-003 must compile any future authority."""

    TASK = "task"
    REPLAN = "replan"
    STOP = "stop"
    ESCALATE = "escalate"


class SupervisorShadowProposalDraft(StrictModel):
    """Minimal untrusted model output with no executable request fields."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/supervisor-shadow-proposal-draft/v1alpha1"
    ] = Field(
        default=SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorShadowProposalDraft"] = "SupervisorShadowProposalDraft"
    snapshot_id: _Identifier = Field(alias="snapshotId")
    snapshot_digest: _Sha256 = Field(alias="snapshotDigest")
    proposal_kind: SupervisorShadowProposalKind = Field(alias="proposalKind")
    rationale: str = Field(min_length=1, max_length=5_000)
    proposal_state: Literal["untrusted-model-output-not-authorized"] = Field(
        default="untrusted-model-output-not-authorized",
        alias="proposalState",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)


_SUPERVISOR_SHADOW_PROPOSAL_DRAFT_WIRE_KEYS = frozenset(
    {
        "apiVersion",
        "kind",
        "snapshotId",
        "snapshotDigest",
        "proposalKind",
        "rationale",
        "proposalState",
        "capabilityGranted",
        "permitGranted",
        "executionAuthorized",
    }
)


def parse_supervisor_shadow_proposal_draft(
    content: bytes,
) -> SupervisorShadowProposalDraft:
    """Strict-decode the exact alias-spelled JSON wire advertised to the Provider."""

    try:
        raw = parse_strict_json_bytes(
            content,
            label="Supervisor Provider draft",
            max_bytes=_MAX_DRAFT_BYTES,
        )
        if type(raw) is not dict:
            raise TypeError("Supervisor draft wire must be a JSON object")
        if not set(raw).issubset(_SUPERVISOR_SHADOW_PROPOSAL_DRAFT_WIRE_KEYS):
            raise ValueError("Supervisor draft wire uses a non-advertised field spelling")
        return SupervisorShadowProposalDraft.model_validate(raw)
    except (TypeError, ValidationError, ValueError) as exc:
        raise SupervisorModelBindingError(
            "Supervisor draft wire differs from its advertised JSON Schema"
        ) from exc


class SupervisorModelSchemaKind(StrEnum):
    WALKING_SHADOW_INPUT = "walking-shadow-input"
    COLLABORATION_SNAPSHOT = "collaboration-snapshot"
    SHADOW_PROPOSAL_DRAFT = "shadow-proposal-draft"


class SupervisorModelSchemaBinding(StrictModel):
    """Code-owned schema identity without embedding attacker-controlled content."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    schema_kind: SupervisorModelSchemaKind = Field(alias="schemaKind")
    schema_id: str = Field(alias="schemaId", min_length=1, max_length=200)
    schema_version: Literal["v1alpha1"] = Field(default="v1alpha1", alias="schemaVersion")
    schema_digest: _Sha256 = Field(alias="schemaDigest")
    schema_content_embedded: Literal[False] = Field(
        default=False,
        alias="schemaContentEmbedded",
    )
    authority_granted: Literal[False] = Field(default=False, alias="authorityGranted")

    @field_validator("schema_content_embedded", "authority_granted", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def require_registered_schema(self) -> Self:
        schema_id, schema_digest = _registered_schema_spec(self.schema_kind)
        if self.schema_id != schema_id or self.schema_digest != schema_digest:
            raise ValueError("Supervisor model schema differs from code authority")
        return self


class SupervisorProviderModelIdentity(StrictModel):
    """Secret-free projection of one exact Provider registration and model revision."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    identity_id: str = Field(default="", alias="identityId", max_length=110)
    identity_digest: str = Field(default="", alias="identityDigest", max_length=64)
    provider_id: str = Field(
        alias="providerId",
        pattern=r"^[a-z0-9][a-z0-9-]{1,30}$",
    )
    endpoint: str = Field(min_length=1, max_length=2_000)
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    model_revision: _Identifier = Field(alias="modelRevision")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    secret_reference_embedded: Literal[False] = Field(
        default=False,
        alias="secretReferenceEmbedded",
    )

    @field_validator("secret_reference_embedded", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @field_validator("model_revision")
    @classmethod
    def reject_mutable_revision_aliases(cls, value: str) -> str:
        if value.casefold() in {"auto", "default", "latest"}:
            raise ValueError("Supervisor model revision must be immutable")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"identity_id", "identity_digest"},
        )
        digest = _supervisor_digest(
            "pajin.supervision.provider-model-identity/v1",
            material,
            max_bytes=_MAX_COMPONENT_BYTES,
        )
        identity_id = f"supervisor-provider-model:{digest}"
        if self.identity_digest and self.identity_digest != digest:
            raise ValueError("Supervisor Provider/model Identity Digest differs")
        if self.identity_id and self.identity_id != identity_id:
            raise ValueError("Supervisor Provider/model Identity ID differs")
        object.__setattr__(self, "identity_digest", digest)
        object.__setattr__(self, "identity_id", identity_id)
        return self


class SupervisorModelConfiguration(StrictModel):
    """Bounded structured-output configuration; no prompt or Tool is part of it."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    configuration_id: str = Field(default="", alias="configurationId", max_length=110)
    configuration_digest: str = Field(
        default="",
        alias="configurationDigest",
        max_length=64,
    )
    protocol: Literal["provider-structured-json"] = "provider-structured-json"
    max_completion_tokens: int = Field(
        default=2_048,
        alias="maxCompletionTokens",
        ge=128,
        le=32_768,
    )
    temperature: float = Field(default=0.0, ge=0.0, le=0.0, allow_inf_nan=False)
    top_p: float = Field(default=1.0, alias="topP", ge=1.0, le=1.0, allow_inf_nan=False)
    seed: int = Field(default=0, ge=0, le=2**63 - 1)
    streaming: Literal[False] = False
    function_tools: tuple[str, ...] = Field(default=(), alias="functionTools", max_length=0)
    prompt_content_bound: Literal[False] = Field(default=False, alias="promptContentBound")
    tool_calls_allowed: Literal[False] = Field(default=False, alias="toolCallsAllowed")

    @field_validator("max_completion_tokens", "seed", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor model integer configuration must be an integer")
        return value

    @field_validator("temperature", mode="before")
    @classmethod
    def require_zero_temperature(cls, value: object) -> float:
        if type(value) not in {int, float} or value != 0:
            raise ValueError("Supervisor model temperature must be numeric zero")
        return 0.0

    @field_validator("top_p", mode="before")
    @classmethod
    def require_one_top_p(cls, value: object) -> float:
        if type(value) not in {int, float} or value != 1:
            raise ValueError("Supervisor model top_p must be numeric one")
        return 1.0

    @field_validator(
        "streaming",
        "prompt_content_bound",
        "tool_calls_allowed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_configuration(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"configuration_id", "configuration_digest"},
        )
        digest = _supervisor_digest(
            "pajin.supervision.model-configuration/v1",
            material,
            max_bytes=_MAX_COMPONENT_BYTES,
        )
        configuration_id = f"supervisor-model-configuration:{digest}"
        if self.configuration_digest and self.configuration_digest != digest:
            raise ValueError("Supervisor Model Configuration Digest differs")
        if self.configuration_id and self.configuration_id != configuration_id:
            raise ValueError("Supervisor Model Configuration ID differs")
        object.__setattr__(self, "configuration_digest", digest)
        object.__setattr__(self, "configuration_id", configuration_id)
        return self


class SupervisorModelBinding(StrictModel):
    """Complete SUP-001 identity binding that cannot invoke or authorize a model."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-model-binding/v1alpha1"] = Field(
        default=SUPERVISOR_MODEL_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorModelBinding"] = "SupervisorModelBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    profile_compilation: LegacyCampaignProfileCompilationAuthority = Field(
        alias="profileCompilation"
    )
    profile_compilation_digest: _Sha256 = Field(alias="profileCompilationDigest")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    common_engine_contract_digest: _Sha256 = Field(alias="commonEngineContractDigest")
    supervisor_role: Literal[AgentRole.SUPERVISOR] = Field(
        default=AgentRole.SUPERVISOR,
        alias="supervisorRole",
    )
    provider_model: SupervisorProviderModelIdentity = Field(alias="providerModel")
    provider_model_digest: _Sha256 = Field(alias="providerModelDigest")
    configuration: SupervisorModelConfiguration
    configuration_digest: _Sha256 = Field(alias="configurationDigest")
    walking_shadow_policy: RegisteredWalkingShadowPolicy = Field(alias="walkingShadowPolicy")
    walking_shadow_policy_digest: _Sha256 = Field(alias="walkingShadowPolicyDigest")
    allowed_input_schemas: tuple[SupervisorModelSchemaBinding, ...] = Field(
        alias="allowedInputSchemas",
        min_length=2,
        max_length=2,
    )
    output_proposal_schema: SupervisorModelSchemaBinding = Field(
        alias="outputProposalSchema"
    )
    binding_state: Literal["shadow-model-bound-not-invocable"] = Field(
        default="shadow-model-bound-not-invocable",
        alias="bindingState",
    )
    shadow_mode: Literal[True] = Field(default=True, alias="shadowMode")
    snapshot_only_input_required: Literal[True] = Field(
        default=True,
        alias="snapshotOnlyInputRequired",
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator("shadow_mode", "snapshot_only_input_required", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        return _require_literal_bool(value, expected=True)

    @field_validator(
        "model_invocation_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        compilation = compile_legacy_campaign_profile(
            self.profile_compilation.source_campaign
        )
        engine_contract = registered_common_campaign_engine_contract()
        policy = walking_shadow_supervisor_policy()
        input_schemas, output_schema = _registered_schema_bindings()
        if (
            self.profile_compilation != compilation
            or self.campaign_digest != compilation.input_digest
            or self.profile_compilation_digest != compilation.authority_digest
            or self.profile_digest != compilation.profile_digest
            or self.common_engine_contract_digest != engine_contract.contract_digest
            or self.provider_model_digest != self.provider_model.identity_digest
            or self.configuration_digest != self.configuration.configuration_digest
            or self.walking_shadow_policy != policy
            or self.walking_shadow_policy_digest != policy.policy_digest
            or self.allowed_input_schemas != input_schemas
            or self.output_proposal_schema != output_schema
        ):
            raise ValueError("Supervisor Model Binding differs from registered authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = _supervisor_digest(
            "pajin.supervision.model-binding/v1",
            material,
            max_bytes=_MAX_BINDING_BYTES,
        )
        binding_id = f"supervisor-model-binding:{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Supervisor Model Binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Supervisor Model Binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


def bind_supervisor_model(
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
) -> SupervisorModelBinding:
    """Bind exact runtime identities without granting model invocation authority."""

    authoritative_campaign = CampaignManifest.model_validate_json(
        campaign.model_dump_json(by_alias=True)
    )
    authoritative_provider = ProviderRegistration.model_validate_json(
        provider_registration.model_dump_json(by_alias=True)
    )
    authoritative_configuration = SupervisorModelConfiguration.model_validate(
        configuration.model_dump(mode="json", by_alias=True)
    )
    compilation = compile_legacy_campaign_profile(authoritative_campaign)
    engine_contract = registered_common_campaign_engine_contract()
    policy = walking_shadow_supervisor_policy()
    input_schemas, output_schema = _registered_schema_bindings()
    provider_model = _provider_model_identity(
        authoritative_provider,
        model_revision=model_revision,
    )
    return SupervisorModelBinding(
        campaignDigest=compilation.input_digest,
        profileCompilation=compilation,
        profileCompilationDigest=compilation.authority_digest,
        profileDigest=compilation.profile_digest,
        commonEngineContractDigest=engine_contract.contract_digest,
        providerModel=provider_model,
        providerModelDigest=provider_model.identity_digest,
        configuration=authoritative_configuration,
        configurationDigest=authoritative_configuration.configuration_digest,
        walkingShadowPolicy=policy,
        walkingShadowPolicyDigest=policy.policy_digest,
        allowedInputSchemas=input_schemas,
        outputProposalSchema=output_schema,
    )


def verify_supervisor_model_binding(
    binding: SupervisorModelBinding,
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
) -> SupervisorModelBinding:
    """Require exact equality with the expected Campaign, Provider, revision, and config."""

    try:
        canonical = SupervisorModelBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
        expected = bind_supervisor_model(
            campaign,
            provider_registration,
            model_revision=model_revision,
            configuration=configuration,
        )
        if canonical != expected:
            raise ValueError("Supervisor Model Binding differs from runtime inputs")
        return canonical.model_copy(deep=True)
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise SupervisorModelBindingError(
            "Supervisor Model Binding verification failed closed"
        ) from exc


def _provider_model_identity(
    registration: ProviderRegistration,
    *,
    model_revision: str,
) -> SupervisorProviderModelIdentity:
    registration_material = registration.model_dump(mode="json", by_alias=True)
    registration_material["allowed_function_tools"] = sorted(
        registration.allowed_function_tools
    )
    registration_digest = _supervisor_digest(
        "pajin.supervision.provider-registration/v1",
        registration_material,
        max_bytes=_MAX_COMPONENT_BYTES,
    )
    return SupervisorProviderModelIdentity(
        providerId=registration.provider_id,
        endpoint=str(registration.endpoint),
        modelId=registration.model,
        modelRevision=model_revision,
        providerRegistrationDigest=registration_digest,
    )


def _registered_schema_bindings() -> tuple[
    tuple[SupervisorModelSchemaBinding, ...],
    SupervisorModelSchemaBinding,
]:
    walking_id, walking_digest = _registered_schema_spec(
        SupervisorModelSchemaKind.WALKING_SHADOW_INPUT
    )
    collaboration_id, collaboration_digest = _registered_schema_spec(
        SupervisorModelSchemaKind.COLLABORATION_SNAPSHOT
    )
    output_id, output_digest = _registered_schema_spec(
        SupervisorModelSchemaKind.SHADOW_PROPOSAL_DRAFT
    )
    return (
        (
            SupervisorModelSchemaBinding(
                schemaKind=SupervisorModelSchemaKind.WALKING_SHADOW_INPUT,
                schemaId=walking_id,
                schemaDigest=walking_digest,
            ),
            SupervisorModelSchemaBinding(
                schemaKind=SupervisorModelSchemaKind.COLLABORATION_SNAPSHOT,
                schemaId=collaboration_id,
                schemaDigest=collaboration_digest,
            ),
        ),
        SupervisorModelSchemaBinding(
            schemaKind=SupervisorModelSchemaKind.SHADOW_PROPOSAL_DRAFT,
            schemaId=output_id,
            schemaDigest=output_digest,
        ),
    )


def _registered_schema_spec(kind: SupervisorModelSchemaKind) -> tuple[str, str]:
    if kind is SupervisorModelSchemaKind.WALKING_SHADOW_INPUT:
        schema_id = "pajin.dev/walking-shadow-input-snapshot/v1alpha1"
        schema = WalkingShadowInputSnapshot.model_json_schema(mode="validation", by_alias=True)
    elif kind is SupervisorModelSchemaKind.COLLABORATION_SNAPSHOT:
        schema_id = "pajin.dev/collaboration-snapshot/v1alpha1"
        schema = CollaborationSnapshot.model_json_schema(mode="validation", by_alias=True)
    else:
        schema_id = SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION
        schema = SupervisorShadowProposalDraft.model_json_schema(
            mode="validation",
            by_alias=True,
        )
    return schema_id, _supervisor_digest(
        f"pajin.supervision.schema/{kind.value}/v1",
        schema,
        max_bytes=_MAX_SCHEMA_BYTES,
    )


def _supervisor_digest(domain: str, value: object, *, max_bytes: int) -> str:
    encoded = canonical_json_bytes(value, label="Supervisor authority", max_bytes=max_bytes)
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + encoded).hexdigest()


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("Supervisor authority boolean must be literal and exact")
    return expected
