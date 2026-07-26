from __future__ import annotations

from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    ToolCapabilityRegistration,
    capability_definition_from_tool,
    capability_registry_from_tools,
    registered_action_capability,
    registered_action_capability_registry,
    tool_spec_digest,
)
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec

DIGEST_A = sha256(b"a").hexdigest()


class _TestTool(Tool):
    spec = ToolSpec(
        tool_id="test.read-surface",
        version="1.2.3",
        description="Read one bounded test surface.",
        risk_tier=ToolRiskTier.T1,
        categories=frozenset({"discovery", "read"}),
        evidence_types=frozenset({"json", "trace"}),
        network_access=True,
        network_request_cost=2,
        parallel_safe=True,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        raise NotImplementedError

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        raise NotImplementedError


def _registration() -> ToolCapabilityRegistration:
    return ToolCapabilityRegistration(
        capabilityId="pajin.discovery.read-surface",
        capabilityVersion="1.0.0",
        toolId="test.read-surface",
        domain="web",
        maturity=CapabilityMaturity.CANARY,
        supportedSurfaceTypes=("http-endpoint",),
        threatClasses=("surface-discovery",),
        preconditions=("campaign-scope-approved",),
        parameterSchemaDigest=DIGEST_A,
        sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
        approvalRequired=False,
        cleanupRequired=False,
    )


def _definition() -> CapabilityDefinition:
    return capability_definition_from_tool(_TestTool.spec, _registration())


def test_tool_capability_definition_is_canonical_and_exactly_bound() -> None:
    first = _definition()
    second = _definition()

    assert first == second
    assert first.capability_digest == second.capability_digest
    assert first.tool.tool_digest == tool_spec_digest(_TestTool.spec)
    assert first.tool.tool_id == _TestTool.spec.tool_id
    assert first.tool.tool_version == _TestTool.spec.version
    assert first.risk_tier is ToolRiskTier.T1
    assert first.evidence_types == ("json", "trace")
    assert first.request_unit_cost == 2
    assert first.network_access
    assert first.parallel_safe


def test_definition_rejects_reordering_and_digest_tampering() -> None:
    raw = _definition().model_dump(mode="json", by_alias=True)
    raw["evidenceTypes"] = ["trace", "json"]
    with pytest.raises(ValidationError, match="unique and sorted"):
        CapabilityDefinition.model_validate(raw)

    raw = _definition().model_dump(mode="json", by_alias=True)
    raw["capabilityDigest"] = DIGEST_A
    with pytest.raises(ValidationError, match="digest differs"):
        CapabilityDefinition.model_validate(raw)


def test_registry_requires_exact_version_and_digest() -> None:
    definition = _definition()
    registry = CapabilityDefinitionRegistry([definition])

    assert registry.resolve(definition.reference()) == definition
    wrong_digest = CapabilityDefinitionRef(
        capabilityId=definition.capability_id,
        capabilityVersion=definition.capability_version,
        capabilityDigest=DIGEST_A,
    )
    with pytest.raises(CapabilityDefinitionError, match="digest differs"):
        registry.resolve(wrong_digest)

    with pytest.raises(CapabilityDefinitionError, match="duplicate"):
        CapabilityDefinitionRegistry([definition, definition])


def test_tool_registry_adapter_detects_live_contract_drift() -> None:
    tools = ToolRegistry()
    tool = _TestTool()
    tools.register(tool)
    registry = capability_registry_from_tools(tools, [_registration()])
    assert registry.definitions() == (_definition(),)

    tool.spec = tool.spec.model_copy(update={"version": "9.9.9"})
    with pytest.raises(CapabilityDefinitionError, match="drifted"):
        capability_registry_from_tools(tools, [_registration()])


def test_tool_adapter_requires_explicit_matching_registration() -> None:
    registration = _registration().model_copy(update={"tool_id": "other.tool"})
    with pytest.raises(CapabilityDefinitionError, match="differs"):
        capability_definition_from_tool(_TestTool.spec, registration)

    tools = ToolRegistry()
    tools.register(_TestTool())
    with pytest.raises(CapabilityDefinitionError, match="unavailable"):
        capability_registry_from_tools(tools, [registration])


def test_graph_action_capability_adapter_preserves_exact_authority() -> None:
    definition = _definition()
    action_capability = registered_action_capability(definition)

    assert action_capability.capability_id == definition.capability_id
    assert action_capability.capability_version == definition.capability_version
    assert action_capability.definition_digest == definition.capability_digest
    assert action_capability.capability_digest != definition.capability_digest
    assert action_capability.tool_id == definition.tool.tool_id
    assert action_capability.tool_version == definition.tool.tool_version
    assert action_capability.tool_digest == definition.tool.tool_digest
    assert action_capability.risk_tier is definition.risk_tier

    action_registry = registered_action_capability_registry([definition])
    assert action_registry.resolve(action_capability.reference()) == action_capability
