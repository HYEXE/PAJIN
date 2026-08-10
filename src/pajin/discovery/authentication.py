"""Bounded OpenAPI authentication discovery over exact HTTP evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from re import fullmatch
from typing import Literal, cast
from urllib.parse import urlsplit

from pajin.discovery.adapters import DiscoverySurfaceKind
from pajin.discovery.admission import SurfaceCandidate
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.http import HTTPAndOpenAPISurfaceAdapter, _is_json_content_type
from pajin.discovery.models import (
    HTTPAuthenticationRequirement,
    HTTPAuthenticationRequirementEntry,
    HTTPAuthenticationScheme,
    HTTPAuthenticationSurfaceLocator,
    HTTPRouteSurfaceLocator,
    http_authentication_surface_locator,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.policy.scope import normalize_target_url
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.tools.http import MAX_HTTP_GET_RESPONSE_BYTES, HTTPGetTool

_MAX_OPENAPI_JSON_DEPTH = 32
_MAX_OPENAPI_JSON_NODES = 4_096
_MAX_SECURITY_SCHEMES = 32
_MAX_SECURITY_REQUIREMENTS = 16
_MAX_REQUIREMENT_SCHEMES = 16
_MAX_SECURITY_SCOPES = 32
_MAX_OAUTH_DECLARED_SCOPES = 128
_OAUTH_FLOW_NAMES = frozenset(
    {"authorizationCode", "clientCredentials", "implicit", "password"}
)
_OPENAPI_COMPONENT_KEY_PATTERN = r"^[A-Za-z0-9._-]{1,200}$"


class HTTPAndOpenAPIAuthenticationSurfaceAdapter:
    """Add non-executable authentication boundaries to DISC-002 HTTP Surfaces."""

    adapter_version = "1.0.0"
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
        "http-authentication",
        "http-endpoint",
        "http-internal-api",
        "http-route",
    )
    requires_trusted_network_receipt = True

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        allowed_methods: Iterable[str] = ("GET", "HEAD", "POST"),
        max_openapi_routes: int = 200,
    ) -> None:
        self._base = HTTPAndOpenAPISurfaceAdapter(
            tool=tool,
            allowed_methods=allowed_methods,
            max_openapi_routes=max_openapi_routes,
        )
        self.tool_id = self._base.tool_id
        self.adapter_id = f"pajin.discovery.http-openapi-authentication:{self.tool_id}"
        self.producer_id = (
            f"pajin.discovery.http-openapi-authentication.v1:{self.tool_id}"
        )

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind the base parser and every authentication extraction boundary."""

        return {
            "baseHTTPAndOpenAPI": self._base.stable_execution_context(),
            "maxSecuritySchemes": _MAX_SECURITY_SCHEMES,
            "maxSecurityRequirements": _MAX_SECURITY_REQUIREMENTS,
            "maxRequirementSchemes": _MAX_REQUIREMENT_SCHEMES,
            "maxSecurityScopes": _MAX_SECURITY_SCOPES,
            "maxOAuthDeclaredScopes": _MAX_OAUTH_DECLARED_SCOPES,
            "supportedSchemeTypes": [
                "apiKey",
                "http",
                "mutualTLS",
                "oauth2",
                "openIdConnect",
            ],
            "authenticationURLsRetained": False,
            "authenticationMaterialRetained": False,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        """Return DISC-002 Surfaces plus declared per-route authentication boundaries."""

        candidates = self._base.extract_surfaces(request, result)
        body, content_type = self._base._validated_http_result(request, result)
        if not _is_json_content_type(content_type):
            return candidates
        document = parse_strict_json_bytes(
            body,
            label="HTTP/OpenAPI authentication response body",
            max_bytes=MAX_HTTP_GET_RESPONSE_BYTES,
            max_depth=_MAX_OPENAPI_JSON_DEPTH,
            max_nodes=_MAX_OPENAPI_JSON_NODES,
        )
        if not isinstance(document, dict) or "openapi" not in document:
            return candidates
        routes = [
            candidate.locator
            for candidate in candidates
            if isinstance(candidate.locator, HTTPRouteSurfaceLocator)
        ]
        candidates.extend(_authentication_candidates(document, routes))
        return candidates


def _authentication_candidates(
    document: dict[str, object],
    routes: list[HTTPRouteSurfaceLocator],
) -> list[SurfaceCandidate]:
    paths = document.get("paths")
    version = document.get("openapi")
    if not isinstance(paths, dict) or not isinstance(version, str):
        raise ValueError("OpenAPI authentication document identity is invalid")
    root_security = document.get("security")
    locators: dict[bytes, HTTPAuthenticationSurfaceLocator] = {}
    for route in routes:
        path_item = paths.get(route.path_template)
        if not isinstance(path_item, dict):
            raise ValueError("OpenAPI authentication route has no source path item")
        operation = path_item.get(route.method.lower())
        if not isinstance(operation, dict):
            raise ValueError("OpenAPI authentication route has no source operation")
        security = operation.get("security", root_security)
        requirements, allows_anonymous = _authentication_requirements(security)
        if not requirements:
            continue
        referenced = {
            entry.scheme_id
            for requirement in requirements
            for entry in requirement.schemes
        }
        schemes, oauth_scopes = _referenced_authentication_schemes(
            document,
            referenced,
            version=version,
        )
        _require_declared_oauth_scopes(requirements, schemes, oauth_scopes)
        locator = http_authentication_surface_locator(
            route=route,
            schemes=schemes,
            requirements=requirements,
            allows_anonymous=allows_anonymous,
        )
        key = canonical_json_bytes(
            locator.model_dump(mode="json"),
            label="HTTP/OpenAPI authentication locator",
        )
        locators[key] = locator
    return [
        SurfaceCandidate(locator=locators[key], confidence=0.95)
        for key in sorted(locators)
    ]


def _authentication_requirements(
    value: object,
) -> tuple[tuple[HTTPAuthenticationRequirement, ...], bool]:
    if value is None or value == []:
        return (), False
    if not isinstance(value, list) or len(value) > _MAX_SECURITY_REQUIREMENTS:
        raise ValueError("OpenAPI security requirements are invalid or exceed the limit")
    requirements: dict[
        tuple[tuple[str, tuple[str, ...]], ...],
        HTTPAuthenticationRequirement,
    ] = {}
    allows_anonymous = False
    for raw_requirement in value:
        if not isinstance(raw_requirement, dict):
            raise ValueError("OpenAPI security requirement must be an object")
        if not raw_requirement:
            if allows_anonymous:
                raise ValueError("OpenAPI security requirements repeat anonymous access")
            allows_anonymous = True
            continue
        if len(raw_requirement) > _MAX_REQUIREMENT_SCHEMES:
            raise ValueError("OpenAPI security requirement exceeds the scheme limit")
        entries: list[HTTPAuthenticationRequirementEntry] = []
        for scheme_id, raw_scopes in raw_requirement.items():
            if (
                not isinstance(scheme_id, str)
                or fullmatch(_OPENAPI_COMPONENT_KEY_PATTERN, scheme_id) is None
                or not isinstance(raw_scopes, list)
                or len(raw_scopes) > _MAX_SECURITY_SCOPES
                or any(not isinstance(scope, str) for scope in raw_scopes)
            ):
                raise ValueError("OpenAPI security requirement entry is invalid")
            entries.append(
                HTTPAuthenticationRequirementEntry(
                    scheme_id=scheme_id,
                    scopes=tuple(sorted(raw_scopes)),
                )
            )
        entries.sort(key=lambda item: item.scheme_id)
        requirement = HTTPAuthenticationRequirement(schemes=tuple(entries))
        key = tuple((entry.scheme_id, entry.scopes) for entry in requirement.schemes)
        if key in requirements:
            raise ValueError("OpenAPI security requirements contain a duplicate")
        requirements[key] = requirement
    return tuple(requirements[key] for key in sorted(requirements)), allows_anonymous


def _referenced_authentication_schemes(
    document: dict[str, object],
    referenced: set[str],
    *,
    version: str,
) -> tuple[tuple[HTTPAuthenticationScheme, ...], dict[str, frozenset[str]]]:
    components = document.get("components")
    if not isinstance(components, dict):
        raise ValueError("OpenAPI authentication requires a components object")
    raw_schemes = components.get("securitySchemes")
    if (
        not isinstance(raw_schemes, dict)
        or len(raw_schemes) > _MAX_SECURITY_SCHEMES
    ):
        raise ValueError("OpenAPI securitySchemes are invalid or exceed the limit")
    if not referenced <= set(raw_schemes):
        raise ValueError("OpenAPI security requirement references an unknown scheme")
    schemes: list[HTTPAuthenticationScheme] = []
    oauth_scopes: dict[str, frozenset[str]] = {}
    for scheme_id in sorted(referenced):
        raw_scheme = raw_schemes[scheme_id]
        if not isinstance(raw_scheme, dict) or "$ref" in raw_scheme:
            raise ValueError("Referenced OpenAPI security scheme must be inline")
        scheme, declared_scopes = _authentication_scheme(
            scheme_id,
            raw_scheme,
            version=version,
        )
        schemes.append(scheme)
        if declared_scopes is not None:
            oauth_scopes[scheme_id] = declared_scopes
    return tuple(schemes), oauth_scopes


def _authentication_scheme(
    scheme_id: str,
    value: dict[str, object],
    *,
    version: str,
) -> tuple[HTTPAuthenticationScheme, frozenset[str] | None]:
    scheme_type = value.get("type")
    if scheme_type == "apiKey":
        name = value.get("name")
        location = value.get("in")
        if not isinstance(name, str) or location not in {"header", "query", "cookie"}:
            raise ValueError("OpenAPI apiKey security scheme is invalid")
        return (
            HTTPAuthenticationScheme(
                scheme_id=scheme_id,
                scheme_type="apiKey",
                location=cast(Literal["header", "query", "cookie"], location),
                parameter_name=name,
            ),
            None,
        )
    if scheme_type == "http":
        http_scheme = value.get("scheme")
        if not isinstance(http_scheme, str):
            raise ValueError("OpenAPI HTTP security scheme is invalid")
        return (
            HTTPAuthenticationScheme(
                scheme_id=scheme_id,
                scheme_type="http",
                http_scheme=http_scheme,
            ),
            None,
        )
    if scheme_type == "oauth2":
        flows = value.get("flows")
        if not isinstance(flows, dict) or not flows or len(flows) > 4:
            raise ValueError("OpenAPI OAuth2 flows are invalid")
        if not set(flows) <= _OAUTH_FLOW_NAMES:
            raise ValueError("OpenAPI OAuth2 flow type is unsupported")
        declared_scopes: set[str] = set()
        for flow_name, raw_flow in flows.items():
            if not isinstance(raw_flow, dict):
                raise ValueError("OpenAPI OAuth2 flow is invalid")
            _validate_oauth_flow(flow_name, raw_flow)
            declared_scopes.update(_declared_scopes(raw_flow.get("scopes")))
            if len(declared_scopes) > _MAX_OAUTH_DECLARED_SCOPES:
                raise ValueError("OpenAPI OAuth2 declared scopes exceed the limit")
        return (
            HTTPAuthenticationScheme(
                scheme_id=scheme_id,
                scheme_type="oauth2",
                oauth_flows=tuple(sorted(flows)),
            ),
            frozenset(declared_scopes),
        )
    if scheme_type == "openIdConnect":
        _validate_nonexecuted_authentication_url(value.get("openIdConnectUrl"))
        return (
            HTTPAuthenticationScheme(
                scheme_id=scheme_id,
                scheme_type="openIdConnect",
            ),
            None,
        )
    if scheme_type == "mutualTLS":
        if not version.startswith("3.1."):
            raise ValueError("OpenAPI mutualTLS requires version 3.1")
        return (
            HTTPAuthenticationScheme(
                scheme_id=scheme_id,
                scheme_type="mutualTLS",
            ),
            None,
        )
    raise ValueError("Referenced OpenAPI security scheme type is unsupported")


def _validate_oauth_flow(flow_name: str, value: dict[str, object]) -> None:
    if flow_name in {"implicit", "authorizationCode"}:
        _validate_nonexecuted_authentication_url(value.get("authorizationUrl"))
    if flow_name in {"password", "clientCredentials", "authorizationCode"}:
        _validate_nonexecuted_authentication_url(value.get("tokenUrl"))
    refresh_url = value.get("refreshUrl")
    if refresh_url is not None:
        _validate_nonexecuted_authentication_url(refresh_url)
    if "scopes" not in value:
        raise ValueError("OpenAPI OAuth2 flow requires scopes")


def _declared_scopes(value: object) -> frozenset[str]:
    if not isinstance(value, dict) or len(value) > _MAX_OAUTH_DECLARED_SCOPES:
        raise ValueError("OpenAPI OAuth2 scopes are invalid or exceed the limit")
    scopes: set[str] = set()
    for scope, description in value.items():
        if (
            not isinstance(scope, str)
            or not scope
            or len(scope) > 200
            or any(character.isspace() for character in scope)
            or not isinstance(description, str)
            or len(description) > 2_000
        ):
            raise ValueError("OpenAPI OAuth2 declared scope is invalid")
        scopes.add(scope)
    return frozenset(scopes)


def _validate_nonexecuted_authentication_url(value: object) -> None:
    if not isinstance(value, str) or len(value) > 2_000:
        raise ValueError("OpenAPI authentication URL is invalid")
    normalized = normalize_target_url(value)
    if urlsplit(normalized).fragment:
        raise ValueError("OpenAPI authentication URL cannot contain a fragment")


def _require_declared_oauth_scopes(
    requirements: tuple[HTTPAuthenticationRequirement, ...],
    schemes: tuple[HTTPAuthenticationScheme, ...],
    oauth_scopes: dict[str, frozenset[str]],
) -> None:
    scheme_by_id = {scheme.scheme_id: scheme for scheme in schemes}
    for requirement in requirements:
        for entry in requirement.schemes:
            scheme = scheme_by_id[entry.scheme_id]
            if (
                scheme.scheme_type == "oauth2"
                and not set(entry.scopes) <= oauth_scopes[entry.scheme_id]
            ):
                raise ValueError(
                    "OpenAPI security requirement uses an undeclared OAuth2 scope"
                )
