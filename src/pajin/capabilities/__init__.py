"""Versioned executable Capability contracts and compatibility adapters."""

from pajin.capabilities.adapters import (
    ToolCapabilityRegistration,
    capability_definition_from_tool,
    capability_registry_from_tools,
    registered_action_capability,
    registered_action_capability_registry,
    tool_spec_digest,
)
from pajin.capabilities.models import (
    CAPABILITY_DEFINITION_API_VERSION,
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    canonical_capability_json,
    capability_definition_digest,
)

__all__ = [
    "CAPABILITY_DEFINITION_API_VERSION",
    "CapabilityDefinition",
    "CapabilityDefinitionError",
    "CapabilityDefinitionRef",
    "CapabilityDefinitionRegistry",
    "CapabilityMaturity",
    "CapabilitySideEffectClass",
    "CapabilityToolBinding",
    "ToolCapabilityRegistration",
    "canonical_capability_json",
    "capability_definition_digest",
    "capability_definition_from_tool",
    "capability_registry_from_tools",
    "registered_action_capability",
    "registered_action_capability_registry",
    "tool_spec_digest",
]
