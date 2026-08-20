"""Product-specific execution ceilings for REDTEAM Control Plane profiles."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from pajin.capabilities.adapters import tool_spec_digest
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.domain.models import CampaignManifest, CampaignMode, ToolRequest, ToolRiskTier
from pajin.graph.authority import ActionProposal, MissionEnvelope
from pajin.tools.ai import AIChatProbeTool

REDTEAM_LLM_PROFILE = "redteam-llm-v1"
REDTEAM_LLM_PROFILE_VERSION = "1.0.0"
REDTEAM_LLM_CAPABILITY_THREATS: Mapping[str, str] = MappingProxyType(
    {
        "pajin.ai.kisa.jailbreak-policy-bypass": "M06",
        "pajin.ai.kisa.system-prompt-disclosure": "M03",
    }
)
REDTEAM_LLM_PROFILE_DIGEST = capability_definition_digest(
    "pajin.control-plane.redteam-llm-profile/v1",
    {
        "capabilities": dict(REDTEAM_LLM_CAPABILITY_THREATS),
        "campaignMode": "ai-redteam",
        "cleanupRequired": False,
        "definitionSurfaceTypes": ["ai-chat-api", "rag-chat-api"],
        "evidenceTypes": ["conversation", "json"],
        "method": "POST",
        "networkAccess": True,
        "parallelSafe": False,
        "profileId": REDTEAM_LLM_PROFILE,
        "profileVersion": REDTEAM_LLM_PROFILE_VERSION,
        "requestUnits": 1,
        "riskTier": "T2",
        "sideEffectClass": "read-only",
        "targetType": "ai-chat-api",
        "toolId": AIChatProbeTool.spec.tool_id,
        "toolVersion": AIChatProbeTool.spec.version,
        "turns": 1,
    },
)
REDTEAM_LLM_RAG_PROFILE = "redteam-llm-rag-v1"
REDTEAM_LLM_RAG_PROFILE_VERSION = "1.0.0"
REDTEAM_LLM_RAG_CAPABILITY_ID = "pajin.ai.kisa.memory-poisoning-persistence"
REDTEAM_LLM_RAG_CAPABILITY_VERSION = "1.1.0"
REDTEAM_LLM_RAG_SCENARIO_ID = "kisa.agent.memory-poisoning-persistence"
REDTEAM_LLM_RAG_THREAT_CLASS = "A04"
REDTEAM_LLM_RAG_REQUEST_UNITS = 2
REDTEAM_LLM_RAG_PROFILE_DIGEST = capability_definition_digest(
    "pajin.control-plane.redteam-llm-rag-profile/v1",
    {
        "capabilities": {
            REDTEAM_LLM_RAG_CAPABILITY_ID: {
                "capabilityVersion": REDTEAM_LLM_RAG_CAPABILITY_VERSION,
                "threatClass": REDTEAM_LLM_RAG_THREAT_CLASS,
            }
        },
        "campaignMode": "ai-redteam",
        "cleanupRequired": False,
        "definitionSurfaceTypes": ["ai-chat-api", "rag-chat-api"],
        "evidenceTypes": ["conversation", "json"],
        "method": "POST",
        "networkAccess": True,
        "parallelSafe": False,
        "profileId": REDTEAM_LLM_RAG_PROFILE,
        "profileVersion": REDTEAM_LLM_RAG_PROFILE_VERSION,
        "requestUnits": REDTEAM_LLM_RAG_REQUEST_UNITS,
        "riskTier": "T2",
        "sideEffectClass": "read-only",
        "targetTypes": ["ai-chat-api", "rag-chat-api"],
        "toolId": AIChatProbeTool.spec.tool_id,
        "toolVersion": AIChatProbeTool.spec.version,
        "turns": 2,
    },
)


class RedteamProfileError(ValueError):
    """Raised when a product profile would widen its registered attack boundary."""


def validate_redteam_llm_profile(
    *,
    campaign: CampaignManifest,
    definition: CapabilityDefinition,
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    request: ToolRequest,
) -> None:
    """Admit one approved single-turn LLM probe without changing Gateway authority."""

    threat_class = REDTEAM_LLM_CAPABILITY_THREATS.get(definition.capability_id)
    expected_tool = AIChatProbeTool.spec
    if (
        envelope.profile_id != REDTEAM_LLM_PROFILE
        or envelope.profile_version != REDTEAM_LLM_PROFILE_VERSION
        or envelope.profile_digest != REDTEAM_LLM_PROFILE_DIGEST
        or threat_class is None
        or definition.capability_version != "1.0.0"
        or definition.domain != "ai-redteam"
        or definition.maturity is not CapabilityMaturity.EXPERIMENTAL
        or definition.supported_surface_types != ("ai-chat-api", "rag-chat-api")
        or definition.threat_classes != (threat_class,)
        or definition.preconditions != ("authorized-target", "bounded-kisa-catalog-scenario")
        or definition.tool.tool_id != expected_tool.tool_id
        or definition.tool.tool_version != expected_tool.version
        or definition.tool.tool_digest != tool_spec_digest(expected_tool)
        or definition.risk_tier is not ToolRiskTier.T2
        or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
        or definition.evidence_types != ("conversation", "json")
        or not definition.network_access
        or definition.approval_required
        or definition.request_unit_cost != 1
        or proposal.reservation.request_units != definition.request_unit_cost
        or definition.cleanup_required
        or definition.parallel_safe
    ):
        raise RedteamProfileError(
            "REDTEAM LLM profile requires an exact registered single-turn KISA Capability"
        )
    if (
        request.tool_id != expected_tool.tool_id
        or request.method != "POST"
        or request.arguments.get("scenario_id")
        not in {
            "kisa.model.jailbreak-policy-bypass",
            "kisa.model.system-prompt-disclosure",
        }
        or request.arguments.get("threat_class") != threat_class
        or not isinstance(request.arguments.get("turns"), list)
        or len(request.arguments["turns"]) != 1
    ):
        raise RedteamProfileError(
            "REDTEAM LLM request differs from its exact single-turn Capability"
        )
    targets = tuple(
        target
        for target in campaign.spec.targets
        if target.type == "ai-chat-api" and target.endpoint == request.target
    )
    if (
        campaign.spec.mode is not CampaignMode.AI_REDTEAM
        or len(targets) != 1
        or threat_class not in campaign.spec.threat_classes
        or "POST" not in campaign.spec.rules_of_engagement.allowed_methods
        or campaign.spec.rules_of_engagement.max_tool_risk_tier < ToolRiskTier.T2
    ):
        raise RedteamProfileError(
            "REDTEAM LLM request is outside the deployed AI Red Team Campaign"
        )


def validate_redteam_llm_rag_profile(
    *,
    campaign: CampaignManifest,
    definition: CapabilityDefinition,
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    request: ToolRequest,
) -> None:
    """Admit exact two-turn A04 authority with a matching Graph reservation."""

    expected_tool = AIChatProbeTool.spec
    if (
        envelope.profile_id != REDTEAM_LLM_RAG_PROFILE
        or envelope.profile_version != REDTEAM_LLM_RAG_PROFILE_VERSION
        or envelope.profile_digest != REDTEAM_LLM_RAG_PROFILE_DIGEST
        or definition.capability_id != REDTEAM_LLM_RAG_CAPABILITY_ID
        or definition.capability_version != REDTEAM_LLM_RAG_CAPABILITY_VERSION
        or definition.domain != "ai-redteam"
        or definition.maturity is not CapabilityMaturity.EXPERIMENTAL
        or definition.supported_surface_types != ("ai-chat-api", "rag-chat-api")
        or definition.threat_classes != (REDTEAM_LLM_RAG_THREAT_CLASS,)
        or definition.preconditions != ("authorized-target", "bounded-kisa-catalog-scenario")
        or definition.tool.tool_id != expected_tool.tool_id
        or definition.tool.tool_version != expected_tool.version
        or definition.tool.tool_digest != tool_spec_digest(expected_tool)
        or definition.risk_tier is not ToolRiskTier.T2
        or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
        or definition.evidence_types != ("conversation", "json")
        or not definition.network_access
        or definition.approval_required
        or definition.request_unit_cost != REDTEAM_LLM_RAG_REQUEST_UNITS
        or proposal.reservation.request_units != definition.request_unit_cost
        or definition.cleanup_required
        or definition.parallel_safe
    ):
        raise RedteamProfileError(
            "REDTEAM LLM/RAG profile requires the exact registered two-turn A04 Capability"
        )
    turns = request.arguments.get("turns")
    if (
        request.tool_id != expected_tool.tool_id
        or request.method != "POST"
        or request.arguments.get("scenario_id") != REDTEAM_LLM_RAG_SCENARIO_ID
        or request.arguments.get("threat_class") != REDTEAM_LLM_RAG_THREAT_CLASS
        or not isinstance(turns, list)
        or len(turns) != REDTEAM_LLM_RAG_REQUEST_UNITS
        or len(turns) != proposal.reservation.request_units
    ):
        raise RedteamProfileError(
            "REDTEAM LLM/RAG request differs from its exact two-turn reservation"
        )
    targets = tuple(
        target
        for target in campaign.spec.targets
        if target.type in {"ai-chat-api", "rag-chat-api"} and target.endpoint == request.target
    )
    if (
        campaign.spec.mode is not CampaignMode.AI_REDTEAM
        or len(targets) != 1
        or REDTEAM_LLM_RAG_THREAT_CLASS not in campaign.spec.threat_classes
        or "POST" not in campaign.spec.rules_of_engagement.allowed_methods
        or campaign.spec.rules_of_engagement.max_tool_risk_tier < ToolRiskTier.T2
    ):
        raise RedteamProfileError(
            "REDTEAM LLM/RAG request is outside the deployed AI Red Team Campaign"
        )


__all__ = [
    "REDTEAM_LLM_CAPABILITY_THREATS",
    "REDTEAM_LLM_PROFILE",
    "REDTEAM_LLM_PROFILE_DIGEST",
    "REDTEAM_LLM_PROFILE_VERSION",
    "REDTEAM_LLM_RAG_CAPABILITY_ID",
    "REDTEAM_LLM_RAG_CAPABILITY_VERSION",
    "REDTEAM_LLM_RAG_PROFILE",
    "REDTEAM_LLM_RAG_PROFILE_DIGEST",
    "REDTEAM_LLM_RAG_PROFILE_VERSION",
    "REDTEAM_LLM_RAG_REQUEST_UNITS",
    "REDTEAM_LLM_RAG_SCENARIO_ID",
    "REDTEAM_LLM_RAG_THREAT_CLASS",
    "RedteamProfileError",
    "validate_redteam_llm_profile",
    "validate_redteam_llm_rag_profile",
]
