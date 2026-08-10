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
    HTTPAndOpenAPIRAGSurfaceAdapter,
    HTTPAuthenticationSurfaceLocator,
    HTTPFileUploadSurfaceLocator,
    HTTPRAGSurfaceLocator,
    HTTPRouteSurfaceLocator,
    http_rag_surface_locator,
    http_route_surface_locator,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.tools.base import ToolRegistry
from pajin.tools.http import HTTPGetTool

NOW = datetime(2026, 7, 29, 4, 0, tzinfo=UTC)
TARGET = "https://staging.example.invalid/openapi.json"


def _request() -> ToolRequest:
    return ToolRequest(
        request_id="http_rag_1",
        agent_id="recon-specialist:rag",
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
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
        "security": [{"BearerAuth": []}],
        "paths": {
            "/documents": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "corpus-ingest",
                        "corpusIds": ["customer-documents"],
                        "indexIds": ["semantic-primary"],
                    },
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["file"],
                                    "properties": {
                                        "file": {
                                            "type": "string",
                                            "format": "binary",
                                        }
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"202": {"description": "accepted"}},
                }
            },
            "/indexes/{index_id}": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "index-management",
                        "corpusIds": ["customer-documents"],
                        "indexIds": ["semantic-primary"],
                    },
                    "responses": {"204": {"description": "updated"}},
                }
            },
            "/search": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "retrieval",
                        "corpusIds": ["customer-documents"],
                        "indexIds": ["semantic-primary"],
                    },
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "results",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            },
                        }
                    },
                }
            },
        },
    }


def _adapter(
    *,
    max_rag_boundaries: int = 32,
) -> HTTPAndOpenAPIRAGSurfaceAdapter:
    return HTTPAndOpenAPIRAGSurfaceAdapter(
        tool=HTTPGetTool(),
        allowed_methods=("GET", "POST"),
        max_rag_boundaries=max_rag_boundaries,
    )


def _rag_locators(candidates: list[object]) -> list[HTTPRAGSurfaceLocator]:
    return [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPRAGSurfaceLocator)
    ]


def test_rag_adapter_preserves_inherited_surfaces_and_explicit_boundaries() -> None:
    candidates = _adapter().extract_surfaces(_request(), _result(_document()))

    assert any(
        isinstance(candidate.locator, HTTPAuthenticationSurfaceLocator)
        for candidate in candidates
    )
    assert any(
        isinstance(candidate.locator, HTTPFileUploadSurfaceLocator)
        for candidate in candidates
    )
    assert sum(
        isinstance(candidate.locator, HTTPRouteSurfaceLocator)
        for candidate in candidates
    ) == 3
    locators = _rag_locators(candidates)
    assert [
        (
            locator.route.path_template,
            locator.boundary,
            locator.corpus_ids,
            locator.index_ids,
        )
        for locator in locators
    ] == [
        (
            "/documents",
            "corpus-ingest",
            ("customer-documents",),
            ("semantic-primary",),
        ),
        (
            "/indexes/{index_id}",
            "index-management",
            ("customer-documents",),
            ("semantic-primary",),
        ),
        (
            "/search",
            "retrieval",
            ("customer-documents",),
            ("semantic-primary",),
        ),
    ]


def test_rag_adapter_is_deterministic_across_openapi_object_order() -> None:
    document = _document()
    reordered = deepcopy(document)
    paths = reordered["paths"]
    assert isinstance(paths, dict)
    reordered["paths"] = dict(reversed(list(paths.items())))

    first = _rag_locators(
        _adapter().extract_surfaces(_request(), _result(document))
    )
    second = _rag_locators(
        _adapter().extract_surfaces(_request(), _result(reordered))
    )

    assert [item.model_dump(mode="json") for item in first] == [
        item.model_dump(mode="json") for item in second
    ]


def test_rag_adapter_never_infers_from_names_descriptions_or_schemas() -> None:
    document = {
        "openapi": "3.1.0",
        "x-pajin-rag": {
            "version": "1",
            "boundary": "retrieval",
            "indexIds": ["ignored-root"],
        },
        "paths": {
            "/rag/retrieve": {
                "x-pajin-rag": {
                    "version": "1",
                    "boundary": "retrieval",
                    "indexIds": ["ignored-path"],
                },
                "post": {
                    "summary": "Retrieve embeddings from the vector index",
                    "description": "RAG corpus query and prompt injection boundary",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {"type": "string"},
                                        "embedding": {
                                            "type": "array",
                                            "items": {"type": "number"},
                                        },
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "retrieved chunks"}},
                },
            }
        },
    }

    candidates = _adapter().extract_surfaces(_request(), _result(document))

    assert not _rag_locators(candidates)


@pytest.mark.parametrize(
    "declaration",
    [
        None,
        [],
        {"version": "2", "boundary": "retrieval", "indexIds": ["primary"]},
        {"version": "1", "boundary": "unknown", "indexIds": ["primary"]},
        {"version": "1", "boundary": "corpus-ingest"},
        {"version": "1", "boundary": "index-management"},
        {"version": "1", "boundary": "retrieval"},
        {
            "version": "1",
            "boundary": "retrieval",
            "indexIds": ["z", "a"],
        },
        {
            "version": "1",
            "boundary": "retrieval",
            "indexIds": ["primary", "primary"],
        },
        {
            "version": "1",
            "boundary": "retrieval",
            "indexIds": ["https://vector.invalid/index"],
        },
        {
            "$ref": "https://schemas.invalid/rag.json",
            "version": "1",
            "boundary": "retrieval",
            "indexIds": ["primary"],
        },
        {
            "version": "1",
            "boundary": "retrieval",
            "index_ids": ["primary"],
        },
    ],
)
def test_rag_adapter_rejects_malformed_or_referenced_declarations(
    declaration: object,
) -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/search": {
                "post": {
                    "x-pajin-rag": declaration,
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    with pytest.raises(ValueError, match="OpenAPI RAG declaration"):
        _adapter().extract_surfaces(_request(), _result(document))


@pytest.mark.parametrize(
    "sensitive_field",
    [
        "document",
        "query",
        "embedding",
        "vectorValues",
        "retrievedContent",
        "url",
    ],
)
def test_rag_adapter_rejects_runtime_data_and_destination_fields(
    sensitive_field: str,
) -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/search": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "retrieval",
                        "indexIds": ["primary"],
                        sensitive_field: "must-not-be-retained",
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    with pytest.raises(ValueError, match="OpenAPI RAG declaration"):
        _adapter().extract_surfaces(_request(), _result(document))


def test_rag_adapter_does_not_retain_operation_text_or_runtime_examples() -> None:
    secret_query = "confidential-query-value"
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/search": {
                "post": {
                    "description": secret_query,
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "retrieval",
                        "indexIds": ["primary"],
                    },
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "string",
                                    "example": secret_query,
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": secret_query}},
                }
            }
        },
    }

    candidates = _adapter().extract_surfaces(_request(), _result(document))
    serialized = json.dumps(
        [
            candidate.locator.model_dump(mode="json")
            for candidate in candidates
        ],
        sort_keys=True,
    )

    assert secret_query not in serialized


def test_rag_adapter_rejects_boundary_overflow() -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            path: {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "retrieval",
                        "indexIds": [f"index-{number}"],
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
            for number, path in enumerate(("/first", "/second"), start=1)
        },
    }

    with pytest.raises(ValueError, match="declarations exceed the limit"):
        _adapter(max_rag_boundaries=1).extract_surfaces(
            _request(),
            _result(document),
        )


def test_rag_locator_rejects_inconsistent_contract_and_copies_route() -> None:
    route = http_route_surface_locator(
        base_url="https://staging.example.invalid/api",
        path_template="/search",
        method="POST",
    )
    locator = http_rag_surface_locator(
        route=route,
        boundary="retrieval",
        corpus_ids=("documents",),
        index_ids=("primary",),
    )

    assert locator.route is not route
    assert locator.route == route
    with pytest.raises(ValidationError, match="index identifier"):
        http_rag_surface_locator(route=route, boundary="retrieval")
    with pytest.raises(ValidationError, match="unique and sorted"):
        http_rag_surface_locator(
            route=route,
            boundary="corpus-ingest",
            corpus_ids=("z", "a"),
        )


def test_rag_adapter_registry_binds_exact_domain_contract() -> None:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIRAGSurfaceAdapter(
        tool=tool,
        allowed_methods=("POST", "GET"),
        max_openapi_routes=25,
        max_file_uploads=12,
        max_rag_boundaries=7,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])

    definition = registry.definitions()[0]

    assert definition.supported_surface_kinds == (
        "http-authentication",
        "http-endpoint",
        "http-file-upload",
        "http-internal-api",
        "http-rag",
        "http-route",
    )
    assert definition.requires_trusted_network_receipt is True
    assert registry.resolve(definition.reference()).adapter is adapter
    context = adapter.stable_execution_context()
    assert context["extensionField"] == "x-pajin-rag"
    assert context["maxRAGBoundaries"] == 7
    assert context["descriptionInference"] is False
    assert context["externalRefResolution"] is False
    assert context["corpusContentRetained"] is False
    assert context["retrievalQueriesRetained"] is False
    assert context["retrievedContentRetained"] is False
    assert context["embeddingsRetained"] is False
    assert context["vectorValuesRetained"] is False
