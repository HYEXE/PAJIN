from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    AI_SECURITY_LOCATOR_SCHEMA,
    AI_SECURITY_SURFACE_TYPE,
    AIAgentSurfaceLocator,
    AIModelSurfaceLocator,
    AISecuritySurface,
    AISecuritySurfaceLocator,
    AISurfaceClass,
    AISurfaceClassificationRegistry,
    AISurfaceRegistryError,
    AttackSurface,
    HTTPRAGSurfaceLocator,
    MCPPromptArgument,
    MCPPromptSurfaceLocator,
    MCPResourceSurfaceLocator,
    MCPResourceTemplateSurfaceLocator,
    MCPServerSurfaceLocator,
    MCPToolSurfaceLocator,
    MCPURLArgument,
    MCPURLToolSurfaceLocator,
    SurfaceLocator,
    ToolInterfaceSurfaceLocator,
    http_rag_surface_locator,
    http_route_surface_locator,
    registered_ai_surface_classification_registry,
    resolve_ai_surface_classification_registry,
    resolve_registered_ai_surface_locator,
    typed_ai_security_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_SHA_A = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64
_SHA_D = "d" * 64
_SHA_E = "e" * 64

_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    "profileSelected",
    "discoveryAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialAccessAuthorized",
    "graphAdmissionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_SURFACE_FALSE_ALIASES = (
    "discoveryObserved",
    "evidenceSealed",
    "graphAdmitted",
    "profileSelected",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialAccessAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)


def _model() -> AIModelSurfaceLocator:
    return AIModelSurfaceLocator(
        providerId="local-openai",
        modelId="Qwen/Qwen3-4B-Instruct-2507",
        modelRevision="sha256:20260822",
        providerRegistrationDigest=_SHA_A,
    )


def _rag() -> HTTPRAGSurfaceLocator:
    return http_rag_surface_locator(
        route=http_route_surface_locator(
            base_url="https://rag.example.test/v1",
            path_template="/indexes/{index_id}/query",
            method="POST",
            request_content_types=("application/json",),
            response_content_types=("application/json",),
        ),
        boundary="retrieval",
        index_ids=("support-index",),
    )


def _agent() -> AIAgentSurfaceLocator:
    return AIAgentSurfaceLocator(
        agentImplementationId="pajin.agent.security-review",
        agentImplementationVersion="1.0.0",
        agentImplementationDigest=_SHA_A,
        providerRegistrationDigest=_SHA_B,
        modelRevision="2026-08-22",
        promptBundleDigest=_SHA_C,
        toolCatalogDigest=_SHA_D,
        runtimeConfigurationDigest=_SHA_E,
    )


def _mcp_server() -> MCPServerSurfaceLocator:
    return MCPServerSurfaceLocator(
        server_id="demo-security",
        protocol_version="2025-06-18",
        capabilities=("prompts", "resources", "tools"),
    )


def _tool() -> ToolInterfaceSurfaceLocator:
    return ToolInterfaceSurfaceLocator(
        registry_id="pajin.tools.core",
        tool_id="ai.chat-probe",
        tool_version="1.0.0",
        input_schema_digest=_SHA_A,
    )


def test_registry_binds_exact_ai_semantics_and_classification_order() -> None:
    registry = registered_ai_surface_classification_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    ai_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.AI
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.surface_type == AI_SECURITY_SURFACE_TYPE
    assert registry.locator_schema == AI_SECURITY_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.AI
    assert registry.domain_graph_type_set == ai_type_set.reference()
    assert ai_type_set.surface_type == AI_SECURITY_SURFACE_TYPE
    assert ai_type_set.locator_schema == AI_SECURITY_LOCATOR_SCHEMA
    assert tuple(
        (item.surface_class.value, item.locator_kind, item.existing_discovery_locator)
        for item in registry.locators
    ) == (
        ("model", "ai-model", False),
        ("rag", "http-rag", True),
        ("agent", "ai-agent", False),
        ("mcp", "mcp-server", True),
        ("mcp", "mcp-prompt", True),
        ("mcp", "mcp-resource", True),
        ("mcp", "mcp-resource-template", True),
        ("tool", "mcp-tool", True),
        ("tool", "mcp-url-tool", True),
        ("tool", "tool-interface", True),
    )
    assert tuple(dict.fromkeys(item.surface_class for item in registry.locators)) == tuple(
        AISurfaceClass
    )
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert len(registry.registry_digest) == 64
    assert AISurfaceClassificationRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    ) == registry


def test_locator_and_complete_registry_resolution_require_exact_references() -> None:
    registry = registered_ai_surface_classification_registry()

    for source in registry.locators:
        resolved = resolve_registered_ai_surface_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_ai_surface_classification_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_digest_class_and_registry_substitution() -> None:
    registry = registered_ai_surface_classification_registry()
    source = registry.locators[0]

    with pytest.raises(AISurfaceRegistryError, match="not registered exactly"):
        resolve_registered_ai_surface_locator(
            source.reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(AISurfaceRegistryError, match="not registered exactly"):
        resolve_registered_ai_surface_locator(
            source.reference().model_copy(update={"surface_class": AISurfaceClass.TOOL})
        )
    with pytest.raises(AISurfaceRegistryError, match="not registered exactly"):
        resolve_ai_surface_classification_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


@pytest.mark.parametrize(
    ("locator", "expected_class"),
    (
        (_model(), AISurfaceClass.MODEL),
        (_rag(), AISurfaceClass.RAG),
        (_agent(), AISurfaceClass.AGENT),
        (_mcp_server(), AISurfaceClass.MCP),
        (_tool(), AISurfaceClass.TOOL),
    ),
)
def test_each_ai_class_becomes_stable_inert_typed_surface(
    locator: AISecuritySurfaceLocator,
    expected_class: AISurfaceClass,
) -> None:
    surface = typed_ai_security_surface(locator=locator)

    assert surface.surface_class is expected_class
    assert surface.locator == locator
    assert surface.locator is not locator
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == f"ai-security-surface_{surface.surface_digest}"
    assert surface.reference().surface_class is expected_class
    assert surface.reference().locator_kind == surface.locator.kind
    assert AISecuritySurface.model_validate(
        surface.model_dump(mode="json", by_alias=True)
    ) == surface


def test_registry_covers_existing_mcp_subsurfaces_without_tool_authority() -> None:
    locators = (
        MCPPromptSurfaceLocator(
            server_id="demo-security",
            prompt_name="review",
            arguments=(MCPPromptArgument(name="text", required=True),),
        ),
        MCPResourceSurfaceLocator(
            server_id="demo-security",
            uri_scheme="internal",
            uri_sha256=_SHA_A,
        ),
        MCPResourceTemplateSurfaceLocator(
            server_id="demo-security",
            uri_scheme="internal",
            template_sha256=_SHA_B,
        ),
        MCPToolSurfaceLocator(
            server_id="demo-security",
            tool_name="inspect_text",
            input_schema_digest=_SHA_C,
            output_schema_digest=_SHA_D,
        ),
        MCPURLToolSurfaceLocator(
            server_id="demo-security",
            tool_name="fetch_url",
            input_schema_digest=_SHA_E,
            url_arguments=(MCPURLArgument(name="url", required=True),),
        ),
    )

    classes = tuple(typed_ai_security_surface(locator=item).surface_class for item in locators)
    assert classes == (
        AISurfaceClass.MCP,
        AISurfaceClass.MCP,
        AISurfaceClass.MCP,
        AISurfaceClass.TOOL,
        AISurfaceClass.TOOL,
    )
    assert all(
        typed_ai_security_surface(locator=item).tool_selection_authorized is False
        for item in locators
    )


def test_typed_model_and_agent_require_immutable_secret_free_identity() -> None:
    model_payload = _model().model_dump(mode="json", by_alias=True)
    model_payload["modelRevision"] = "latest"
    with pytest.raises(ValidationError, match="must be immutable"):
        AIModelSurfaceLocator.model_validate(model_payload)

    model_payload = _model().model_dump(mode="json", by_alias=True)
    model_payload["secretReferenceEmbedded"] = True
    with pytest.raises(ValidationError):
        AIModelSurfaceLocator.model_validate(model_payload)

    agent_payload = _agent().model_dump(mode="json", by_alias=True)
    agent_payload["agentImplementationVersion"] = "default"
    with pytest.raises(ValidationError, match="must be immutable"):
        AIAgentSurfaceLocator.model_validate(agent_payload)

    assert "secret" not in AIAgentSurfaceLocator.model_fields
    assert "endpoint" not in AIAgentSurfaceLocator.model_fields


def test_registry_and_typed_surface_carry_explicit_non_authority_markers() -> None:
    registry = registered_ai_surface_classification_registry()
    surface = typed_ai_security_surface(locator=_model())
    registry_payload = registry.model_dump(mode="json", by_alias=True)
    surface_payload = surface.model_dump(mode="json", by_alias=True)

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    assert {
        "campaign_profile",
        "capability",
        "scope",
        "approval",
        "permit",
        "tool",
        "worker",
        "request",
        "observation",
        "evidence",
    }.isdisjoint(AISecuritySurface.model_fields)


def test_ai_registry_does_not_change_existing_discovery_or_attack_surface_wire() -> None:
    registry = registered_ai_surface_classification_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "domain_classification" not in HTTPRAGSurfaceLocator.model_fields
    assert "surface_class" not in AttackSurface.model_fields
    assert "surface_type" not in AttackSurface.model_fields

    with pytest.raises(ValidationError):
        TypeAdapter(SurfaceLocator).validate_python(
            _model().model_dump(mode="json", by_alias=True)
        )
    with pytest.raises(ValidationError):
        TypeAdapter(SurfaceLocator).validate_python(
            _agent().model_dump(mode="json", by_alias=True)
        )


@pytest.mark.parametrize(
    ("path", "value", "match"),
    (
        (("locators", 0, "surfaceClass"), "tool", "code authority"),
        (
            ("locators", 0, "sourceModelId"),
            "pajin.discovery.models.HTTPSurfaceLocator",
            "code authority",
        ),
        (("locators", 0, "locatorDigest"), "0" * 64, "Digest differs"),
        (("locators",), "reverse", "code authority"),
        (("domainClassification", "domain"), "web", "code authority"),
        (("registryDigest",), "0" * 64, "Digest differs"),
    ),
)
def test_registry_rejects_class_model_order_domain_and_digest_drift(
    path: tuple[str | int, ...],
    value: str,
    match: str,
) -> None:
    payload = deepcopy(
        registered_ai_surface_classification_registry().model_dump(
            mode="json",
            by_alias=True,
        )
    )
    if path == ("locators",):
        payload["locators"].reverse()
    else:
        target = payload
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = value

    with pytest.raises(ValidationError, match=match):
        AISurfaceClassificationRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
def test_registry_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_ai_surface_classification_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        AISurfaceClassificationRegistry.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        AISurfaceClassificationRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
def test_typed_surface_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = typed_ai_security_surface(locator=_agent()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        AISecuritySurface.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        AISecuritySurface.model_validate(payload)


def test_typed_surface_rejects_class_registry_domain_digest_and_injected_authority() -> None:
    original = typed_ai_security_surface(locator=_model()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("classificationRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "web"),
        (None, "surfaceClass", "tool"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "ai-security-surface_" + "0" * 64),
        (None, "capability", {"capabilityId": "unregistered"}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            AISecuritySurface.model_validate(payload)
