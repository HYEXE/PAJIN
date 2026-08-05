"""PERMIT-002 deterministic compilation of general attack action intent."""

from __future__ import annotations

from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities import (
    CapabilityAuthorityBinding,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CodeBackedCapabilityRef,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.hypothesis import AttackHypothesisSet, SurfaceBoundPlan
from pajin.domain.models import CampaignManifest, StrictModel, ToolRequest
from pajin.supervision.action_proposal import (
    GeneralAttackActionProposal,
    GeneralAttackActionProposalError,
    verify_general_attack_action_proposal,
)

GENERAL_ATTACK_COMPILED_INTENT_API_VERSION: Literal[
    "pajin.dev/general-attack-compiled-intent/v1alpha1"
] = "pajin.dev/general-attack-compiled-intent/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_COMPILED_INTENT_BYTES = 8 * 1024 * 1024
_GENERAL_ATTACK_COMPILER_AGENT_ID = "pajin.supervision.general-attack-action-compiler"


class GeneralAttackActionCompilerError(RuntimeError):
    """Raised when PERMIT-002 cannot compile an exact non-executable intent."""


class GeneralAttackCompiledIntent(StrictModel):
    """Content-addressed CAP-002 output that is not GRAPH or Permit authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/general-attack-compiled-intent/v1alpha1"] = Field(
        default=GENERAL_ATTACK_COMPILED_INTENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GeneralAttackCompiledIntent"] = "GeneralAttackCompiledIntent"
    intent_id: str = Field(default="", alias="intentId", max_length=96)
    intent_digest: str = Field(default="", alias="intentDigest", max_length=64)
    source_proposal: GeneralAttackActionProposal = Field(alias="sourceProposal")
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    materializer_authority: CapabilityAuthorityBinding = Field(alias="materializerAuthority")
    action_compiler_authority: CapabilityAuthorityBinding = Field(alias="actionCompilerAuthority")
    request: ToolRequest
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    target_digest: _Sha256 = Field(alias="targetDigest")
    compilation_state: Literal["compiled-not-permitted"] = Field(
        default="compiled-not-permitted",
        alias="compilationState",
    )
    materializer_applied: Literal[True] = Field(default=True, alias="materializerApplied")
    action_compiler_applied: Literal[True] = Field(default=True, alias="actionCompilerApplied")
    tool_request_compiled: Literal[True] = Field(default=True, alias="toolRequestCompiled")
    capability_activated: Literal[False] = Field(default=False, alias="capabilityActivated")
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    graph_action_proposal_created: Literal[False] = Field(
        default=False,
        alias="graphActionProposalCreated",
    )
    mission_envelope_bound: Literal[False] = Field(default=False, alias="missionEnvelopeBound")
    graph_decision_bound: Literal[False] = Field(default=False, alias="graphDecisionBound")
    budget_reserved: Literal[False] = Field(default=False, alias="budgetReserved")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )

    @field_validator(
        "materializer_applied",
        "action_compiler_applied",
        "tool_request_compiled",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        return _require_literal_bool(value, expected=True)

    @field_validator(
        "capability_activated",
        "capability_granted",
        "graph_action_proposal_created",
        "mission_envelope_bound",
        "graph_decision_bound",
        "budget_reserved",
        "permit_granted",
        "execution_authorized",
        "scope_expansion_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_intent(self) -> Self:
        proposal = self.source_proposal
        if self.code_backed_capability.capability != proposal.action_definition:
            raise ValueError("Compiled intent Capability differs from its source Proposal")
        if self.materializer_authority.role != CapabilityAuthorityRole.MATERIALIZER:
            raise ValueError("Compiled intent Materializer authority has another role")
        if self.action_compiler_authority.role != CapabilityAuthorityRole.ACTION_COMPILER:
            raise ValueError("Compiled intent Action Compiler authority has another role")
        expected_request_id = _compiled_request_id(
            proposal,
            self.code_backed_capability,
            self.materializer_authority,
            self.action_compiler_authority,
        )
        target_digest = sha256(self.request.target.encode("utf-8", errors="strict")).hexdigest()
        if (
            self.request.request_id != expected_request_id
            or self.request.agent_id != _GENERAL_ATTACK_COMPILER_AGENT_ID
            or self.request.method != proposal.action_method
            or not _same_canonical_json(
                self.request.arguments,
                proposal.arguments,
                label="Compiled intent Proposal arguments",
            )
            or self.target_digest != proposal.target.endpoint_digest
            or self.target_digest != target_digest
        ):
            raise ValueError("Compiled intent expands or changes Proposal action semantics")
        if self.request_digest != capability_tool_request_digest(self.request):
            raise ValueError("Compiled intent Tool Request Digest differs")
        if self.normalized_parameters_digest != capability_normalized_parameters_digest(
            self.request.arguments
        ):
            raise ValueError("Compiled intent Normalized Parameters Digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"intent_id", "intent_digest"},
        )
        digest = _compiled_intent_digest(material)
        intent_id = f"general-attack-compiled-intent:{digest}"
        if self.intent_digest and self.intent_digest != digest:
            raise ValueError("General Attack Compiled Intent Digest differs")
        if self.intent_id and self.intent_id != intent_id:
            raise ValueError("General Attack Compiled Intent ID differs")
        object.__setattr__(self, "intent_digest", digest)
        object.__setattr__(self, "intent_id", intent_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="General Attack Compiled Intent",
            max_bytes=_MAX_COMPILED_INTENT_BYTES,
        )
        return self


def compile_general_attack_action_intent(
    proposal: GeneralAttackActionProposal,
    campaign: CampaignManifest,
    hypothesis_set: AttackHypothesisSet,
    plan: SurfaceBoundPlan,
    task_digest: str,
    action_definition: CapabilityDefinitionRef,
    definitions: CapabilityDefinitionRegistry,
    code_backed_capability: CodeBackedCapabilityRef,
    authorities: CapabilityAuthorityRegistry,
) -> GeneralAttackCompiledIntent:
    """Re-open PERMIT-001 and invoke exact CAP-002 roles without granting execution."""

    try:
        canonical_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        canonical_proposal = verify_general_attack_action_proposal(
            proposal,
            canonical_campaign,
            hypothesis_set,
            plan,
            task_digest,
            action_definition,
            definitions,
        )
        if not isinstance(authorities, CapabilityAuthorityRegistry):
            raise TypeError("General attack compilation requires a Capability Authority Registry")
        canonical_reference = CodeBackedCapabilityRef.model_validate(
            code_backed_capability.model_dump(mode="json", by_alias=True)
        )
        manifest = authorities.resolve(canonical_reference)
        if manifest.capability != canonical_proposal.action_definition:
            raise ValueError("Code-backed Capability differs from the source Proposal")
        materializer = authorities.authority(
            canonical_reference,
            CapabilityAuthorityRole.MATERIALIZER,
        )
        compiler = authorities.authority(
            canonical_reference,
            CapabilityAuthorityRole.ACTION_COMPILER,
        )
        definition = definitions.resolve(canonical_proposal.action_definition)
        targets = tuple(
            item
            for item in canonical_campaign.spec.targets
            if item.id == canonical_proposal.target.target_id
        )
        if len(targets) != 1:
            raise ValueError("General attack compilation Target is absent or ambiguous")
        seed_request = ToolRequest(
            request_id=_compiled_request_id(
                canonical_proposal,
                canonical_reference,
                materializer.binding,
                compiler.binding,
            ),
            agent_id=_GENERAL_ATTACK_COMPILER_AGENT_ID,
            tool_id=definition.tool.tool_id,
            target=targets[0].endpoint,
            method=canonical_proposal.action_method,
            arguments=canonical_proposal.arguments,
        )
        materialized = materializer.materialize(canonical_proposal.arguments)
        if not _same_canonical_json(
            materialized,
            canonical_proposal.arguments,
            label="Capability Materializer Proposal arguments",
        ):
            raise ValueError("Capability Materializer expanded or changed Proposal arguments")
        compiled = compiler.compile(seed_request, materialized)
        if not _same_canonical_json(
            compiled.model_dump(mode="json", by_alias=True),
            seed_request.model_dump(mode="json", by_alias=True),
            label="Capability Compiler exact Tool Request",
        ):
            raise ValueError("Capability Compiler changed the exact ORCH Tool Request")
        target_digest = sha256(compiled.target.encode("utf-8", errors="strict")).hexdigest()
        if target_digest != canonical_proposal.target.endpoint_digest:
            raise ValueError("Capability Compiler Target differs from the source Proposal")
        authorities.resolve(canonical_reference)
        return GeneralAttackCompiledIntent(
            sourceProposal=canonical_proposal,
            codeBackedCapability=canonical_reference,
            materializerAuthority=materializer.binding,
            actionCompilerAuthority=compiler.binding,
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
            targetDigest=target_digest,
        )
    except GeneralAttackActionCompilerError:
        raise
    except (
        AttributeError,
        CapabilityAuthorityError,
        GeneralAttackActionProposalError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise GeneralAttackActionCompilerError(
            "General attack deterministic Action compilation failed closed"
        ) from exc


def verify_general_attack_compiled_intent(
    value: GeneralAttackCompiledIntent,
    proposal: GeneralAttackActionProposal,
    campaign: CampaignManifest,
    hypothesis_set: AttackHypothesisSet,
    plan: SurfaceBoundPlan,
    task_digest: str,
    action_definition: CapabilityDefinitionRef,
    definitions: CapabilityDefinitionRegistry,
    code_backed_capability: CodeBackedCapabilityRef,
    authorities: CapabilityAuthorityRegistry,
) -> GeneralAttackCompiledIntent:
    """Recompile from current sources and exact-match one PERMIT-002 intent."""

    try:
        canonical = GeneralAttackCompiledIntent.model_validate(
            value.model_dump(mode="json", by_alias=True)
        )
        expected = compile_general_attack_action_intent(
            proposal,
            campaign,
            hypothesis_set,
            plan,
            task_digest,
            action_definition,
            definitions,
            code_backed_capability,
            authorities,
        )
        if canonical != expected:
            raise ValueError("General attack Compiled Intent differs from current authorities")
        return canonical.model_copy(deep=True)
    except GeneralAttackActionCompilerError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise GeneralAttackActionCompilerError(
            "General attack Compiled Intent verification failed closed"
        ) from exc


def _compiled_intent_digest(material: object) -> str:
    canonical_json_bytes(
        material,
        label="General Attack Compiled Intent identity",
        max_bytes=_MAX_COMPILED_INTENT_BYTES,
    )
    return discovery_digest("pajin.action.general-attack-compiled-intent/v1", material)


def _compiled_request_id(
    proposal: GeneralAttackActionProposal,
    code_backed_capability: CodeBackedCapabilityRef,
    materializer: CapabilityAuthorityBinding,
    compiler: CapabilityAuthorityBinding,
) -> str:
    digest = discovery_digest(
        "pajin.action.general-attack-compiled-request/v1",
        {
            "sourceProposalDigest": proposal.proposal_digest,
            "codeBackedCapability": code_backed_capability.model_dump(
                mode="json",
                by_alias=True,
            ),
            "materializerAuthorityDigest": materializer.authority_digest,
            "actionCompilerAuthorityDigest": compiler.authority_digest,
        },
    )
    return f"general_attack_{digest}"


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("General attack Compiled Intent boolean must be literal and exact")
    return expected


def _same_canonical_json(left: object, right: object, *, label: str) -> bool:
    return canonical_json_bytes(
        left,
        label=f"{label} left",
        max_bytes=_MAX_COMPILED_INTENT_BYTES,
    ) == canonical_json_bytes(
        right,
        label=f"{label} right",
        max_bytes=_MAX_COMPILED_INTENT_BYTES,
    )
