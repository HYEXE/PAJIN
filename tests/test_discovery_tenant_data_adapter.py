from __future__ import annotations

import json
from base64 import b64encode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPITenantDataSurfaceAdapter,
    HTTPDataResponseSurfaceLocator,
    HTTPRAGSurfaceLocator,
    HTTPTenantRetrievalSurfaceLocator,
    HTTPTenantSelector,
    http_data_response_surface_locator,
    http_rag_surface_locator,
    http_route_surface_locator,
    http_tenant_retrieval_surface_locator,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.tools.base import ToolRegistry
from pajin.tools.http import HTTPGetTool

NOW = datetime(2026, 8, 10, 4, 0, tzinfo=UTC)
TARGET = "https://staging.example.invalid/openapi.json"


def _request() -> ToolRequest:
    return ToolRequest(
        request_id="http_tenant_data_1",
        agent_id="recon-specialist:tenant-data",
        tool_id=HTTPGetTool.spec.tool_id,
        target=TARGET,
        method="GET",
    )


def _result(document: object) -> ToolResult:
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    request = _request()
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        data={
            "target": TARGET,
            "status": 200,
            "contentType": "application/json",
            "bodyPreview": body.decode(),
            "bodySha256": sha256(body).hexdigest(),
            "responseBodyBase64": b64encode(body).decode("ascii"),
        },
    )


def _document() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/tenant-search": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "retrieval",
                        "indexIds": ["customer-search"],
                    },
                    "x-pajin-tenant-retrieval": {
                        "version": "1",
                        "tenantSelector": {
                            "location": "header",
                            "name": "X-Tenant-ID",
                        },
                    },
                    "x-pajin-data-response": {
                        "version": "1",
                        "dataClasses": ["customer-content", "support-record"],
                    },
                    "requestBody": {
                        "content": {"application/json": {"schema": {"type": "object"}}}
                    },
                    "responses": {
                        "200": {
                            "description": "results",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        }
                    },
                }
            }
        },
    }


def _adapter(
    *,
    max_tenant_data_boundaries: int = 32,
) -> HTTPAndOpenAPITenantDataSurfaceAdapter:
    return HTTPAndOpenAPITenantDataSurfaceAdapter(
        tool=HTTPGetTool(),
        allowed_methods=("GET", "POST"),
        max_tenant_data_boundaries=max_tenant_data_boundaries,
    )


def test_tenant_data_adapter_preserves_rag_and_emits_exact_declarations() -> None:
    candidates = _adapter().extract_surfaces(_request(), _result(_document()))
    retrievals = [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPRAGSurfaceLocator)
    ]
    tenant_retrievals = [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPTenantRetrievalSurfaceLocator)
    ]
    data_responses = [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPDataResponseSurfaceLocator)
    ]

    assert len(retrievals) == len(tenant_retrievals) == len(data_responses) == 1
    tenant = tenant_retrievals[0]
    data = data_responses[0]
    assert tenant.retrieval == retrievals[0]
    assert tenant.tenant_selector.model_dump(mode="json") == {
        "location": "header",
        "name": "X-Tenant-ID",
    }
    assert data.route == tenant.retrieval.route
    assert data.data_classes == ("customer-content", "support-record")
    serialized = json.dumps(
        [candidate.locator.model_dump(mode="json") for candidate in candidates],
        sort_keys=True,
    )
    assert "tenantValue" not in serialized
    assert "retrievedContent" not in serialized


def test_tenant_data_adapter_is_deterministic_across_openapi_order() -> None:
    document = _document()
    reordered = deepcopy(document)
    operation = reordered["paths"]["/tenant-search"]["post"]  # type: ignore[index]
    assert isinstance(operation, dict)
    reordered["paths"]["/tenant-search"]["post"] = dict(  # type: ignore[index]
        reversed(list(operation.items()))
    )

    first = _adapter().extract_surfaces(_request(), _result(document))
    second = _adapter().extract_surfaces(_request(), _result(reordered))

    assert [item.locator.model_dump(mode="json") for item in first] == [
        item.locator.model_dump(mode="json") for item in second
    ]


def test_tenant_data_adapter_never_infers_from_names_or_schemas() -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/cross-tenant-data-exposure": {
                "post": {
                    "summary": "Retrieve another tenant's confidential records",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"tenant_id": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "sensitive data",
                            "content": {"application/json": {}},
                        }
                    },
                }
            }
        },
    }

    candidates = _adapter().extract_surfaces(_request(), _result(document))

    assert not any(
        isinstance(
            candidate.locator,
            (HTTPTenantRetrievalSurfaceLocator, HTTPDataResponseSurfaceLocator),
        )
        for candidate in candidates
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("x-pajin-tenant-retrieval", None, "must be an object"),
        (
            "x-pajin-tenant-retrieval",
            {"version": "2", "tenantSelector": {"location": "header", "name": "X-Tenant"}},
            "tenant retrieval declaration is invalid",
        ),
        (
            "x-pajin-tenant-retrieval",
            {
                "version": "1",
                "tenantSelector": {"location": "header", "name": "X-Tenant"},
                "tenantValue": "other-tenant",
            },
            "tenant retrieval declaration is invalid",
        ),
        ("x-pajin-data-response", [], "must be an object"),
        (
            "x-pajin-data-response",
            {"version": "1", "dataClasses": ["z", "a"]},
            "data response declaration is invalid",
        ),
        (
            "x-pajin-data-response",
            {"version": "1", "dataClasses": ["tenant-acme"]},
            "data response declaration is invalid",
        ),
        (
            "x-pajin-data-response",
            {
                "version": "1",
                "dataClasses": ["customer-content"],
                "responseExample": {"secret": "must-not-be-retained"},
            },
            "data response declaration is invalid",
        ),
    ],
)
def test_tenant_data_adapter_rejects_malformed_or_runtime_declarations(
    field: str,
    value: object,
    message: str,
) -> None:
    document = _document()
    operation = document["paths"]["/tenant-search"]["post"]  # type: ignore[index]
    assert isinstance(operation, dict)
    operation[field] = value

    with pytest.raises(ValueError, match=message):
        _adapter().extract_surfaces(_request(), _result(document))


def test_tenant_retrieval_requires_exact_rag_retrieval() -> None:
    document = _document()
    operation = document["paths"]["/tenant-search"]["post"]  # type: ignore[index]
    assert isinstance(operation, dict)
    operation["x-pajin-rag"] = {
        "version": "1",
        "boundary": "index-management",
        "indexIds": ["customer-search"],
    }

    with pytest.raises(ValueError, match="requires one exact RAG retrieval"):
        _adapter().extract_surfaces(_request(), _result(document))


def test_tenant_path_selector_must_exist_on_bound_route() -> None:
    document = _document()
    operation = document["paths"]["/tenant-search"]["post"]  # type: ignore[index]
    assert isinstance(operation, dict)
    operation["x-pajin-tenant-retrieval"] = {
        "version": "1",
        "tenantSelector": {"location": "path", "name": "tenant_id"},
    }

    with pytest.raises(ValueError, match="tenant retrieval declaration is invalid"):
        _adapter().extract_surfaces(_request(), _result(document))


def test_tenant_data_locator_factories_copy_and_validate_nested_authority() -> None:
    route = http_route_surface_locator(
        base_url="https://staging.example.invalid/api",
        path_template="/tenants/{tenant_id}/search",
        method="POST",
        response_content_types=("application/json",),
    )
    retrieval = http_rag_surface_locator(
        route=route,
        boundary="retrieval",
        index_ids=("customer-search",),
    )
    selector = HTTPTenantSelector(location="path", name="tenant_id")

    tenant = http_tenant_retrieval_surface_locator(
        retrieval=retrieval,
        tenant_selector=selector,
    )
    data = http_data_response_surface_locator(
        route=route,
        data_classes=("customer-content",),
    )

    assert tenant.retrieval is not retrieval
    assert tenant.tenant_selector is not selector
    assert data.route is not route
    with pytest.raises(ValidationError, match="requires a RAG retrieval"):
        http_tenant_retrieval_surface_locator(
            retrieval=http_rag_surface_locator(
                route=route,
                boundary="index-management",
                index_ids=("customer-search",),
            ),
            tenant_selector=selector,
        )
    with pytest.raises(ValidationError, match="response content type"):
        http_data_response_surface_locator(
            route=http_route_surface_locator(
                base_url="https://staging.example.invalid/api",
                path_template="/empty",
                method="GET",
            ),
            data_classes=("customer-content",),
        )


def test_tenant_data_adapter_registry_binds_exact_contract() -> None:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPITenantDataSurfaceAdapter(
        tool=tool,
        allowed_methods=("POST", "GET"),
        max_tenant_data_boundaries=7,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])

    definition = registry.definitions()[0]

    assert definition.supported_surface_kinds == (
        "http-authentication",
        "http-data-response",
        "http-endpoint",
        "http-file-upload",
        "http-rag",
        "http-route",
        "http-tenant-retrieval",
    )
    assert definition.requires_trusted_network_receipt is True
    assert registry.resolve(definition.reference()).adapter is adapter
    context = adapter.stable_execution_context()
    assert context["tenantRetrievalExtensionField"] == "x-pajin-tenant-retrieval"
    assert context["dataResponseExtensionField"] == "x-pajin-data-response"
    assert context["maxTenantDataBoundaries"] == 7
    assert context["descriptionInference"] is False
    assert context["tenantValuesRetained"] is False
    assert context["retrievalQueriesRetained"] is False
    assert context["responseContentRetained"] is False
