from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    DiscoveryAdapterError,
    DiscoveryAdapterReference,
    DiscoveryAdapterRegistry,
    MCPInterfaceSurfaceAdapter,
    TrustedSurfaceProducer,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import RegisteredMCPTool, demo_mcp_tool

_INPUT_SCHEMA_DIGEST = "a" * 64


def _registered_adapter() -> tuple[
    ToolRegistry,
    RegisteredMCPTool,
    MCPInterfaceSurfaceAdapter,
    DiscoveryAdapterRegistry,
]:
    tools = ToolRegistry()
    tool = demo_mcp_tool()
    tools.register(tool)
    adapter = MCPInterfaceSurfaceAdapter(
        tool=tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    return tools, tool, adapter, registry


def test_registry_resolves_only_exact_versioned_adapter_reference() -> None:
    _, tool, adapter, registry = _registered_adapter()

    definitions = registry.definitions()

    assert len(definitions) == 1
    definition = definitions[0]
    assert definition.adapter_id == adapter.adapter_id
    assert definition.adapter_version == "1.0.0"
    assert definition.producer_id == adapter.producer_id
    assert definition.tool.tool_id == tool.spec.tool_id
    assert definition.tool.tool_version == tool.spec.version
    assert definition.supported_surface_kinds == ("tool-interface",)
    assert definition.requires_trusted_network_receipt is False
    assert registry.resolve(definition.reference()).definition == definition
    legacy_payload = definition.model_dump(mode="json", by_alias=True)
    legacy_payload.pop("requiresTrustedNetworkReceipt")
    assert type(definition).model_validate(legacy_payload).reference() == definition.reference()

    with pytest.raises(DiscoveryAdapterError, match="not registered"):
        registry.resolve(
            DiscoveryAdapterReference(
                adapterId=adapter.adapter_id,
                adapterVersion="latest",
                adapterDigest=definition.adapter_digest,
            )
        )
    with pytest.raises(DiscoveryAdapterError, match="digest differs"):
        registry.resolve(definition.reference().model_copy(update={"adapter_digest": "b" * 64}))


def test_adapter_definition_is_frozen_and_rejects_unknown_surface_kind() -> None:
    _, _, adapter, registry = _registered_adapter()
    definition = registry.definitions()[0]

    with pytest.raises(ValidationError):
        definition.adapter_version = "2.0.0"  # type: ignore[misc]

    adapter.supported_surface_kinds = ("unknown",)  # type: ignore[assignment]
    with pytest.raises(DiscoveryAdapterError, match="unavailable or has drifted"):
        registry.resolve(definition.reference())


def test_registry_rejects_duplicate_unregistered_and_sensitive_adapters() -> None:
    tools = ToolRegistry()
    tool = demo_mcp_tool()
    tools.register(tool)
    adapter = MCPInterfaceSurfaceAdapter(
        tool=tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )

    with pytest.raises(DiscoveryAdapterError, match="duplicate ID and version"):
        DiscoveryAdapterRegistry(tools=tools, adapters=[adapter, adapter])

    unregistered_tool = demo_mcp_tool()
    unregistered = MCPInterfaceSurfaceAdapter(
        tool=unregistered_tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    with pytest.raises(DiscoveryAdapterError, match="Tool is unavailable"):
        DiscoveryAdapterRegistry(tools=ToolRegistry(), adapters=[unregistered])

    sensitive = _SensitiveAdapter(
        tool=tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    with pytest.raises(DiscoveryAdapterError, match="stable execution context"):
        DiscoveryAdapterRegistry(tools=tools, adapters=[sensitive])


def test_registry_detects_adapter_and_tool_contract_drift() -> None:
    _, _, adapter, registry = _registered_adapter()
    reference = registry.definitions()[0].reference()

    adapter._remote_tool_id = "changed-remote-tool"
    with pytest.raises(DiscoveryAdapterError, match="changed after registration"):
        registry.resolve(reference)

    _, tool, _, registry = _registered_adapter()
    reference = registry.definitions()[0].reference()
    tool.spec = tool.spec.model_copy(update={"version": "9.9.9"})
    with pytest.raises(DiscoveryAdapterError, match="drifted"):
        registry.resolve(reference)


def test_adapter_selection_rejects_duplicates_and_multiple_interpreters_per_tool() -> None:
    tools = ToolRegistry()
    tool = demo_mcp_tool()
    tools.register(tool)
    first = MCPInterfaceSurfaceAdapter(
        tool=tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    second = MCPInterfaceSurfaceAdapter(
        tool=tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    second.adapter_id = f"{first.adapter_id}.alternate"
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[first, second])
    references = tuple(definition.reference() for definition in registry.definitions())

    with pytest.raises(DiscoveryAdapterError, match="contains a duplicate"):
        registry.select([references[0], references[0]])
    with pytest.raises(DiscoveryAdapterError, match="multiple interpreters"):
        registry.select(references)
    with pytest.raises(DiscoveryAdapterError, match="cannot be empty"):
        registry.select([])


def test_registry_backed_producer_requires_the_same_tool_authority_root() -> None:
    _, _, _, registry = _registered_adapter()
    reference = registry.definitions()[0].reference()

    with pytest.raises(DiscoveryAdapterError, match="same ToolRegistry"):
        TrustedSurfaceProducer.from_adapter_registry(
            tools=ToolRegistry(),
            registry=registry,
            adapter_references=[reference],
        )


class _SensitiveAdapter(MCPInterfaceSurfaceAdapter):
    def stable_execution_context(self) -> Mapping[str, object]:
        return {"nested": {"apiToken": "must-not-be-bound"}}
