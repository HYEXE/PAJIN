"""Compatibility adapters from current Tool contracts to Capability definitions."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import ConfigDict, Field

from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    capability_definition_digest,
)
from pajin.domain.models import StrictModel
from pajin.graph.authority import ActionCapabilityRegistry, RegisteredActionCapability
from pajin.tools.base import ToolRegistry, ToolSpec


class ToolCapabilityRegistration(StrictModel):
    """Explicit metadata needed to expose one existing Tool as a Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability_id: str = Field(
        alias="capabilityId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    capability_version: str = Field(
        alias="capabilityVersion",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    tool_id: str = Field(
        alias="toolId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    domain: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    maturity: CapabilityMaturity
    supported_surface_types: tuple[str, ...] = Field(
        alias="supportedSurfaceTypes",
        min_length=1,
        max_length=100,
    )
    threat_classes: tuple[str, ...] = Field(
        alias="threatClasses",
        min_length=1,
        max_length=100,
    )
    preconditions: tuple[str, ...] = Field(default=(), max_length=100)
    parameter_schema_digest: str = Field(
        alias="parameterSchemaDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    side_effect_class: CapabilitySideEffectClass = Field(alias="sideEffectClass")
    approval_required: bool = Field(alias="approvalRequired")
    cleanup_required: bool = Field(alias="cleanupRequired")


def tool_spec_digest(spec: ToolSpec) -> str:
    """Fingerprint the exact frozen ToolSpec used by the current Tool Registry."""

    snapshot = _canonical_tool_spec(spec)
    material = {
        "toolId": snapshot.tool_id,
        "version": snapshot.version,
        "description": snapshot.description,
        "riskTier": int(snapshot.risk_tier),
        "categories": sorted(snapshot.categories),
        "evidenceTypes": sorted(snapshot.evidence_types),
        "networkAccess": snapshot.network_access,
        "networkRequestCost": snapshot.network_request_cost,
        "parallelSafe": snapshot.parallel_safe,
    }
    return capability_definition_digest("pajin.capability.tool-spec/v1", material)


def capability_definition_from_tool(
    spec: ToolSpec,
    registration: ToolCapabilityRegistration,
) -> CapabilityDefinition:
    """Bind explicit Capability metadata to one exact existing ToolSpec."""

    snapshot = _canonical_tool_spec(spec)
    if snapshot.tool_id != registration.tool_id:
        raise CapabilityDefinitionError(
            "Capability registration Tool differs from the registered ToolSpec"
        )
    return CapabilityDefinition(
        capabilityId=registration.capability_id,
        capabilityVersion=registration.capability_version,
        domain=registration.domain,
        maturity=registration.maturity,
        supportedSurfaceTypes=registration.supported_surface_types,
        threatClasses=registration.threat_classes,
        preconditions=registration.preconditions,
        parameterSchemaDigest=registration.parameter_schema_digest,
        tool=CapabilityToolBinding(
            toolId=snapshot.tool_id,
            toolVersion=snapshot.version,
            toolDigest=tool_spec_digest(snapshot),
        ),
        riskTier=snapshot.risk_tier,
        sideEffectClass=registration.side_effect_class,
        evidenceTypes=tuple(sorted(snapshot.evidence_types)),
        networkAccess=snapshot.network_access,
        approvalRequired=registration.approval_required,
        requestUnitCost=snapshot.network_request_cost,
        cleanupRequired=registration.cleanup_required,
        parallelSafe=snapshot.parallel_safe,
    )


def capability_registry_from_tools(
    tools: ToolRegistry,
    registrations: Iterable[ToolCapabilityRegistration],
) -> CapabilityDefinitionRegistry:
    """Build an exact Capability registry without inferring security metadata."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Capability Tool adapter requires a ToolRegistry")
    definitions: list[CapabilityDefinition] = []
    for registration in registrations:
        try:
            canonical = ToolCapabilityRegistration.model_validate(
                registration.model_dump(mode="json", by_alias=True)
            )
            tools.tool(canonical.tool_id)
            spec = tools.spec(canonical.tool_id)
        except (AttributeError, KeyError, RuntimeError, ValueError) as exc:
            raise CapabilityDefinitionError(
                "Capability Tool registration is unavailable or has drifted"
            ) from exc
        definitions.append(capability_definition_from_tool(spec, canonical))
    return CapabilityDefinitionRegistry(definitions)


def registered_action_capability(
    definition: CapabilityDefinition,
) -> RegisteredActionCapability:
    """Adapt one canonical definition to GRAPH-006's exact Permit contract."""

    canonical = CapabilityDefinition.model_validate(
        definition.model_dump(mode="json", by_alias=True)
    )
    return RegisteredActionCapability(
        capabilityId=canonical.capability_id,
        capabilityVersion=canonical.capability_version,
        definitionDigest=canonical.capability_digest,
        toolId=canonical.tool.tool_id,
        toolVersion=canonical.tool.tool_version,
        toolDigest=canonical.tool.tool_digest,
        riskTier=canonical.risk_tier,
    )


def registered_action_capability_registry(
    definitions: Iterable[CapabilityDefinition],
) -> ActionCapabilityRegistry:
    """Build the GRAPH-006 compiler registry from exact Capability definitions."""

    return ActionCapabilityRegistry(registered_action_capability(item) for item in definitions)


def _canonical_tool_spec(spec: ToolSpec) -> ToolSpec:
    try:
        return ToolSpec.model_validate(spec.model_dump(mode="python"))
    except (AttributeError, ValueError) as exc:
        raise CapabilityDefinitionError("Tool does not expose a canonical ToolSpec") from exc
