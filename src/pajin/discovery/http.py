"""Bounded HTTP and OpenAPI discovery over exact HTTPGetTool evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from hashlib import sha256
from re import fullmatch
from urllib.parse import urljoin, urlsplit, urlunsplit

from pydantic import ConfigDict, Field

from pajin.discovery.adapters import DiscoverySurfaceKind
from pajin.discovery.admission import SurfaceCandidate
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.models import (
    HTTPRouteSurfaceLocator,
    http_route_surface_locator,
    http_surface_locator,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.policy.scope import normalize_target_url
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.tools.base import decode_bounded_response_body
from pajin.tools.http import (
    MAX_HTTP_GET_RESPONSE_BASE64_CHARS,
    MAX_HTTP_GET_RESPONSE_BYTES,
    HTTPGetTool,
)

_OPENAPI_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"})
_OPENAPI_METHOD_FIELDS = frozenset(method.lower() for method in _OPENAPI_METHODS)
_OPENAPI_PATH_ITEM_METADATA = frozenset({"$ref", "description", "parameters", "servers", "summary"})
_MAX_OPENAPI_SERVERS = 8
_MAX_OPENAPI_PATHS = 100
_MAX_OPENAPI_CONTENT_TYPES = 32
_MAX_OPENAPI_JSON_DEPTH = 32
_MAX_OPENAPI_JSON_NODES = 4_096
_DEFAULT_MAX_OPENAPI_ROUTES = 200
_MEDIA_TYPE_PATTERN = r"^[a-z0-9!#$&^_.+*-]+/[a-z0-9!#$&^_.+*-]+$"


class _SealedHTTPGetData(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    target: str = Field(min_length=1, max_length=2_000)
    status: int = Field(ge=200, lt=300)
    content_type: str | None = Field(default=None, alias="contentType", max_length=1_000)
    body_preview: str = Field(alias="bodyPreview", max_length=4_096)
    body_sha256: str = Field(alias="bodySha256", pattern=r"^[a-f0-9]{64}$")
    response_body_base64: str = Field(
        alias="responseBodyBase64",
        max_length=MAX_HTTP_GET_RESPONSE_BASE64_CHARS,
    )


class HTTPAndOpenAPISurfaceAdapter:
    """Interpret one exact HTTP GET result and bounded inline OpenAPI routes."""

    adapter_version = "1.0.0"
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
        "http-endpoint",
        "http-route",
    )
    requires_trusted_network_receipt = True

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        allowed_methods: Iterable[str] = ("GET", "HEAD", "POST"),
        max_openapi_routes: int = _DEFAULT_MAX_OPENAPI_ROUTES,
    ) -> None:
        if not isinstance(tool, HTTPGetTool):
            raise TypeError("HTTP/OpenAPI Surface adapter requires HTTPGetTool")
        methods = tuple(sorted({_canonical_method(method) for method in allowed_methods}))
        if not methods or "GET" not in methods:
            raise ValueError("HTTP/OpenAPI Surface adapter requires GET authority")
        if (
            isinstance(max_openapi_routes, bool)
            or not isinstance(max_openapi_routes, int)
            or not 1 <= max_openapi_routes <= 499
        ):
            raise ValueError("HTTP/OpenAPI route limit must be between 1 and 499")
        self.tool_id = tool.spec.tool_id
        self.adapter_id = f"pajin.discovery.http-openapi:{self.tool_id}"
        self.producer_id = f"pajin.discovery.http-openapi.v1:{self.tool_id}"
        self._tool_version = tool.spec.version
        self._allowed_methods = methods
        self._max_openapi_routes = max_openapi_routes

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind every non-secret choice that changes HTTP route interpretation."""

        return {
            "toolId": self.tool_id,
            "toolVersion": self._tool_version,
            "allowedMethods": list(self._allowed_methods),
            "maxResponseBytes": MAX_HTTP_GET_RESPONSE_BYTES,
            "maxOpenAPIRoutes": self._max_openapi_routes,
            "maxOpenAPIServers": _MAX_OPENAPI_SERVERS,
            "maxOpenAPIPaths": _MAX_OPENAPI_PATHS,
            "supportedOpenAPIVersions": ["3.0", "3.1"],
            "sameOriginServersOnly": True,
            "externalRefResolution": False,
            "yamlParsing": False,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        """Return the fetched endpoint plus safe inline OpenAPI route declarations."""

        body, content_type = self._validated_http_result(request, result)
        candidates = [
            SurfaceCandidate(
                locator=http_surface_locator(url=request.target, method="GET"),
                confidence=1.0,
            )
        ]
        if not _is_json_content_type(content_type):
            return candidates
        document = parse_strict_json_bytes(
            body,
            label="HTTP/OpenAPI response body",
            max_bytes=MAX_HTTP_GET_RESPONSE_BYTES,
            max_depth=_MAX_OPENAPI_JSON_DEPTH,
            max_nodes=_MAX_OPENAPI_JSON_NODES,
        )
        if not isinstance(document, dict):
            return candidates
        has_version = "openapi" in document
        has_paths = "paths" in document
        if not has_version and not has_paths:
            return candidates
        if not has_version or not has_paths:
            raise ValueError("OpenAPI response requires both version and paths")
        candidates.extend(self._openapi_candidates(request.target, document))
        return candidates

    def _validated_http_result(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> tuple[bytes, str | None]:
        if (
            request.tool_id != self.tool_id
            or result.tool_id != self.tool_id
            or result.request_id != request.request_id
            or request.method != "GET"
            or request.arguments
            or not result.success
            or result.error is not None
        ):
            raise ValueError("HTTP discovery result identity is invalid")
        data = _SealedHTTPGetData.model_validate(result.data)
        if data.target != request.target:
            raise ValueError("HTTP discovery result target differs from its request")
        body = decode_bounded_response_body(
            data.response_body_base64,
            max_bytes=MAX_HTTP_GET_RESPONSE_BYTES,
        )
        if (
            sha256(body).hexdigest() != data.body_sha256
            or body.decode("utf-8", errors="replace") != data.body_preview
        ):
            raise ValueError("HTTP discovery body evidence is inconsistent")
        return body, data.content_type

    def _openapi_candidates(
        self,
        request_target: str,
        document: dict[str, object],
    ) -> list[SurfaceCandidate]:
        version = document.get("openapi")
        if not isinstance(version, str) or fullmatch(r"3\.(?:0|1)\.[0-9]+", version) is None:
            raise ValueError("OpenAPI version is unsupported")
        raw_paths = document.get("paths")
        if not isinstance(raw_paths, dict) or len(raw_paths) > _MAX_OPENAPI_PATHS:
            raise ValueError("OpenAPI paths are invalid or exceed the path limit")
        servers = _openapi_servers(request_target, document.get("servers"))
        routes: dict[bytes, HTTPRouteSurfaceLocator] = {}
        for path_template, raw_path_item in raw_paths.items():
            if not isinstance(path_template, str):
                raise ValueError("OpenAPI path key must be text")
            if path_template.startswith("x-"):
                continue
            if not path_template.startswith("/") or not isinstance(raw_path_item, dict):
                raise ValueError("OpenAPI path item is invalid")
            _reject_unsupported_path_item_fields(raw_path_item)
            for raw_method, operation in raw_path_item.items():
                method = raw_method.upper()
                if method not in _OPENAPI_METHODS:
                    continue
                if raw_method != raw_method.lower() or not isinstance(operation, dict):
                    raise ValueError("OpenAPI operation is invalid")
                if "servers" in operation:
                    raise ValueError("OpenAPI operation-level server overrides are unsupported")
                if method not in self._allowed_methods:
                    continue
                request_content_types = _operation_request_content_types(operation)
                response_content_types = _operation_response_content_types(operation)
                for server in servers:
                    locator = http_route_surface_locator(
                        base_url=server,
                        path_template=path_template,
                        method=method,
                        request_content_types=request_content_types,
                        response_content_types=response_content_types,
                    )
                    key = canonical_json_bytes(
                        locator.model_dump(mode="json"),
                        label="HTTP/OpenAPI route locator",
                    )
                    routes[key] = locator
                    if len(routes) > self._max_openapi_routes:
                        raise ValueError("OpenAPI response exceeded the route limit")
        return [SurfaceCandidate(locator=routes[key], confidence=0.95) for key in sorted(routes)]


def _canonical_method(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("HTTP/OpenAPI allowed method must be text")
    method = value.upper()
    if method not in _OPENAPI_METHODS:
        raise ValueError("HTTP/OpenAPI allowed method is unsupported")
    return method


def _normalized_content_type(value: str | None) -> str | None:
    if value is None:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("HTTP response Content-Type contains control characters")
    media_type = value.partition(";")[0].strip().lower()
    if fullmatch(_MEDIA_TYPE_PATTERN, media_type) is None:
        raise ValueError("HTTP response Content-Type is invalid")
    return media_type


def _is_json_content_type(value: str | None) -> bool:
    media_type = _normalized_content_type(value)
    return media_type == "application/json" or bool(
        media_type is not None and media_type.endswith("+json")
    )


def _openapi_servers(request_target: str, value: object) -> tuple[str, ...]:
    request_url = normalize_target_url(request_target)
    request_parts = urlsplit(request_url)
    request_origin = (request_parts.scheme, request_parts.netloc)
    if value is None:
        return (urlunsplit((*request_origin, "/", "", "")),)
    if not isinstance(value, list) or not value or len(value) > _MAX_OPENAPI_SERVERS:
        raise ValueError("OpenAPI servers are invalid or exceed the server limit")
    servers: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            raise ValueError("OpenAPI server entry is invalid")
        raw_url = item["url"]
        if "{" in raw_url or "}" in raw_url:
            raise ValueError("OpenAPI server variables are unsupported")
        server = normalize_target_url(urljoin(request_url, raw_url))
        parts = urlsplit(server)
        if (parts.scheme, parts.netloc) != request_origin or parts.query:
            raise ValueError("OpenAPI server must use the request origin without a query")
        path = parts.path.rstrip("/") or "/"
        servers.add(urlunsplit((parts.scheme, parts.netloc, path, "", "")))
    return tuple(sorted(servers))


def _reject_unsupported_path_item_fields(path_item: dict[str, object]) -> None:
    for key in path_item:
        if not isinstance(key, str):
            raise ValueError("OpenAPI path item field must be text")
        if (
            key.lower() not in _OPENAPI_METHOD_FIELDS
            and key not in _OPENAPI_PATH_ITEM_METADATA
            and not key.startswith("x-")
        ):
            raise ValueError("OpenAPI path item contains an unsupported field")
        if key == "servers":
            raise ValueError("OpenAPI path-level server overrides are unsupported")


def _operation_request_content_types(operation: dict[str, object]) -> tuple[str, ...]:
    request_body = operation.get("requestBody")
    if request_body is None:
        return ()
    if not isinstance(request_body, dict):
        raise ValueError("OpenAPI requestBody is invalid")
    if "$ref" in request_body:
        return ()
    return _content_types(request_body.get("content"), label="request")


def _operation_response_content_types(operation: dict[str, object]) -> tuple[str, ...]:
    responses = operation.get("responses")
    if not isinstance(responses, dict) or not responses:
        raise ValueError("OpenAPI operation responses are invalid")
    values: set[str] = set()
    for response in responses.values():
        if not isinstance(response, dict):
            raise ValueError("OpenAPI response entry is invalid")
        if "$ref" in response:
            continue
        values.update(_content_types(response.get("content"), label="response"))
        if len(values) > _MAX_OPENAPI_CONTENT_TYPES:
            raise ValueError("OpenAPI response content types exceed the limit")
    return tuple(sorted(values))


def _content_types(value: object, *, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, dict) or len(value) > _MAX_OPENAPI_CONTENT_TYPES:
        raise ValueError(f"OpenAPI {label} content is invalid or exceeds the limit")
    normalized = {_openapi_media_type(item) for item in value}
    return tuple(sorted(normalized))


def _openapi_media_type(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("OpenAPI content type must be text")
    media_type = value.lower()
    wildcard_is_valid = (
        "*" not in media_type
        or media_type == "*/*"
        or (media_type.count("*") == 1 and media_type.endswith("/*"))
    )
    if (
        value != value.strip()
        or fullmatch(_MEDIA_TYPE_PATTERN, media_type) is None
        or not wildcard_is_valid
    ):
        raise ValueError("OpenAPI content type is invalid")
    return media_type
