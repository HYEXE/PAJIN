from __future__ import annotations

import json
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIAuthenticationSurfaceAdapter,
    HTTPAuthenticationRequirement,
    HTTPAuthenticationRequirementEntry,
    HTTPAuthenticationScheme,
    HTTPAuthenticationSurfaceLocator,
    http_authentication_surface_locator,
    http_route_surface_locator,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.tools.base import ToolRegistry
from pajin.tools.http import HTTPGetTool

NOW = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
TARGET = "https://staging.example.invalid/openapi.json"


def _request() -> ToolRequest:
    return ToolRequest(
        request_id="http_authentication_1",
        agent_id="recon-specialist:authentication",
        tool_id=HTTPGetTool.spec.tool_id,
        target=TARGET,
        method="GET",
    )


def _result(
    document: object,
    *,
    content_type: str = "application/json",
) -> ToolResult:
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
            "contentType": content_type,
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
                "ApiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                },
                "BearerAuth": {
                    "type": "http",
                    "scheme": "Bearer",
                    "bearerFormat": "JWT",
                },
                "DocumentOAuth": {
                    "type": "oauth2",
                    "flows": {
                        "clientCredentials": {
                            "tokenUrl": "https://identity.example.invalid/oauth/token",
                            "scopes": {
                                "read:documents": "Read documents",
                            },
                        }
                    },
                },
            }
        },
        "security": [
            {"BearerAuth": []},
            {"DocumentOAuth": ["read:documents"]},
            {},
        ],
        "paths": {
            "/documents/{document_id}": {
                "get": {
                    "responses": {
                        "200": {"content": {"application/json": {}}},
                    }
                },
                "post": {
                    "security": [{"ApiKey": []}],
                    "requestBody": {
                        "content": {"application/json": {}},
                    },
                    "responses": {
                        "202": {"content": {"application/json": {}}},
                    },
                },
            },
            "/public": {
                "get": {
                    "security": [],
                    "responses": {"204": {"description": "public"}},
                }
            },
        },
    }


def _adapter() -> HTTPAndOpenAPIAuthenticationSurfaceAdapter:
    return HTTPAndOpenAPIAuthenticationSurfaceAdapter(
        tool=HTTPGetTool(),
        allowed_methods=("GET", "POST"),
    )


def _authentication_locators(
    candidates: list[object],
) -> list[HTTPAuthenticationSurfaceLocator]:
    return [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPAuthenticationSurfaceLocator)
    ]


def test_authentication_adapter_preserves_openapi_security_alternatives() -> None:
    candidates = _adapter().extract_surfaces(_request(), _result(_document()))

    assert [candidate.locator.kind for candidate in candidates].count(
        "http-authentication"
    ) == 2
    locators = _authentication_locators(candidates)
    get_locator = next(item for item in locators if item.route.method == "GET")
    post_locator = next(item for item in locators if item.route.method == "POST")

    assert get_locator.route.path_template == "/documents/{document_id}"
    assert get_locator.allows_anonymous is True
    assert [scheme.scheme_id for scheme in get_locator.schemes] == [
        "BearerAuth",
        "DocumentOAuth",
    ]
    assert [scheme.scheme_type for scheme in get_locator.schemes] == ["http", "oauth2"]
    assert get_locator.schemes[0].http_scheme == "bearer"
    assert get_locator.schemes[1].oauth_flows == ("clientCredentials",)
    assert [
        [(entry.scheme_id, entry.scopes) for entry in requirement.schemes]
        for requirement in get_locator.requirements
    ] == [
        [("BearerAuth", ())],
        [("DocumentOAuth", ("read:documents",))],
    ]

    assert post_locator.allows_anonymous is False
    assert post_locator.schemes == (
        HTTPAuthenticationScheme(
            scheme_id="ApiKey",
            scheme_type="apiKey",
            location="header",
            parameter_name="X-API-Key",
        ),
    )
    assert all(item.route.path_template != "/public" for item in locators)


def test_authentication_adapter_is_deterministic_and_does_not_retain_auth_urls() -> None:
    document = _document()
    first = _adapter().extract_surfaces(_request(), _result(document))
    reversed_document = {
        **document,
        "paths": dict(reversed(list(document["paths"].items()))),  # type: ignore[union-attr]
    }
    second = _adapter().extract_surfaces(_request(), _result(reversed_document))

    first_wire = [candidate.locator.model_dump(mode="json") for candidate in first]
    second_wire = [candidate.locator.model_dump(mode="json") for candidate in second]
    assert first_wire == second_wire
    authentication_wire = json.dumps(
        [
            locator.model_dump(mode="json")
            for locator in _authentication_locators(first)
        ]
    )
    assert "identity.example.invalid" not in authentication_wire
    assert "oauth/token" not in authentication_wire


def test_authentication_adapter_supports_openid_connect_and_openapi_31_mutual_tls() -> None:
    document = _document()
    components = document["components"]
    assert isinstance(components, dict)
    schemes = components["securitySchemes"]
    assert isinstance(schemes, dict)
    schemes.update(
        {
            "OpenID": {
                "type": "openIdConnect",
                "openIdConnectUrl": "https://identity.example.invalid/.well-known/openid-configuration",
            },
            "ClientCert": {"type": "mutualTLS"},
        }
    )
    paths = document["paths"]
    assert isinstance(paths, dict)
    route = paths["/public"]
    assert isinstance(route, dict)
    operation = route["get"]
    assert isinstance(operation, dict)
    operation["security"] = [{"OpenID": ["profile"]}, {"ClientCert": []}]

    locators = _authentication_locators(
        _adapter().extract_surfaces(_request(), _result(document))
    )
    public = next(item for item in locators if item.route.path_template == "/public")

    assert [scheme.scheme_type for scheme in public.schemes] == [
        "mutualTLS",
        "openIdConnect",
    ]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda document: document["security"].insert(0, {"Unknown": []}),  # type: ignore[union-attr]
            "unknown scheme",
        ),
        (
            lambda document: document["components"]["securitySchemes"].__setitem__(  # type: ignore[index,union-attr]
                "BearerAuth",
                {"$ref": "#/components/securitySchemes/Elsewhere"},
            ),
            "must be inline",
        ),
        (
            lambda document: document["security"].__setitem__(  # type: ignore[union-attr]
                1,
                {"DocumentOAuth": ["write:documents"]},
            ),
            "undeclared OAuth2 scope",
        ),
        (
            lambda document: document["security"].append({}),  # type: ignore[union-attr]
            "repeat anonymous",
        ),
        (
            lambda document: document["security"].__setitem__(  # type: ignore[union-attr]
                0,
                {"BearerAuth": ["admin"]},
            ),
            "scopes require",
        ),
    ],
)
def test_authentication_adapter_rejects_ambiguous_or_unbound_security(
    mutator: object,
    message: str,
) -> None:
    document = _document()
    assert callable(mutator)
    mutator(document)

    with pytest.raises(ValueError, match=message):
        _adapter().extract_surfaces(_request(), _result(document))


def test_authentication_adapter_rejects_mutual_tls_in_openapi_30() -> None:
    document = _document()
    document["openapi"] = "3.0.3"
    components = document["components"]
    assert isinstance(components, dict)
    schemes = components["securitySchemes"]
    assert isinstance(schemes, dict)
    schemes["ClientCert"] = {"type": "mutualTLS"}
    document["security"] = [{"ClientCert": []}]

    with pytest.raises(ValueError, match=r"requires version 3\.1"):
        _adapter().extract_surfaces(_request(), _result(document))


def test_authentication_locator_rejects_noncanonical_or_inconsistent_contracts() -> None:
    route = http_route_surface_locator(
        base_url="https://staging.example.invalid/api",
        path_template="/documents/{document_id}",
        method="GET",
    )
    bearer = HTTPAuthenticationScheme(
        scheme_id="BearerAuth",
        scheme_type="http",
        http_scheme="bearer",
    )
    requirement = HTTPAuthenticationRequirement(
        schemes=(
            HTTPAuthenticationRequirementEntry(
                scheme_id="BearerAuth",
                scopes=(),
            ),
        )
    )

    locator = http_authentication_surface_locator(
        route=route,
        schemes=(bearer,),
        requirements=(requirement,),
    )
    assert locator.route is not route

    with pytest.raises(ValidationError, match="exactly match"):
        http_authentication_surface_locator(
            route=route,
            schemes=(
                bearer,
                HTTPAuthenticationScheme(
                    scheme_id="Unused",
                    scheme_type="http",
                    http_scheme="basic",
                ),
            ),
            requirements=(requirement,),
        )
    with pytest.raises(ValidationError, match="scopes require"):
        HTTPAuthenticationSurfaceLocator(
            route=route,
            schemes=(bearer,),
            requirements=(
                HTTPAuthenticationRequirement(
                    schemes=(
                        HTTPAuthenticationRequirementEntry(
                            scheme_id="BearerAuth",
                            scopes=("admin",),
                        ),
                    )
                ),
            ),
        )
    with pytest.raises(ValidationError, match="cannot contain whitespace"):
        HTTPAuthenticationScheme(
            scheme_id="ApiKey",
            scheme_type="apiKey",
            location="header",
            parameter_name="X API Key",
        )
    with pytest.raises(ValidationError, match="must be text"):
        HTTPAuthenticationScheme.model_validate(
            {
                "scheme_id": "OAuth",
                "scheme_type": "oauth2",
                "oauth_flows": ["clientCredentials", 1],
            }
        )


def test_authentication_adapter_registry_binds_exact_domain_contract() -> None:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIAuthenticationSurfaceAdapter(
        tool=tool,
        allowed_methods=("POST", "GET"),
        max_openapi_routes=25,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])

    definition = registry.definitions()[0]

    assert definition.supported_surface_kinds == (
        "http-authentication",
        "http-endpoint",
        "http-internal-api",
        "http-route",
    )
    assert definition.requires_trusted_network_receipt is True
    assert registry.resolve(definition.reference()).adapter is adapter
    context = adapter.stable_execution_context()
    assert context["authenticationMaterialRetained"] is False
    assert context["authenticationURLsRetained"] is False
