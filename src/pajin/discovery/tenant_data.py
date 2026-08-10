"""Bounded tenant retrieval and data-response discovery over exact OpenAPI evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Literal

from pydantic import ConfigDict, Field, ValidationError, field_validator

from pajin.discovery.adapters import DiscoverySurfaceKind
from pajin.discovery.admission import SurfaceCandidate
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.http import _is_json_content_type
from pajin.discovery.models import (
    HTTPDataClass,
    HTTPDataResponseSurfaceLocator,
    HTTPRAGSurfaceLocator,
    HTTPRouteSurfaceLocator,
    HTTPTenantRetrievalSurfaceLocator,
    HTTPTenantSelector,
    http_data_response_surface_locator,
    http_tenant_retrieval_surface_locator,
)
from pajin.discovery.rag import HTTPAndOpenAPIRAGSurfaceAdapter
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.tools.http import MAX_HTTP_GET_RESPONSE_BYTES, HTTPGetTool

_MAX_OPENAPI_JSON_DEPTH = 32
_MAX_OPENAPI_JSON_NODES = 4_096
_DEFAULT_MAX_TENANT_DATA_BOUNDARIES = 32
_MAX_DATA_CLASSES = 6
_TENANT_RETRIEVAL_EXTENSION_FIELD = "x-pajin-tenant-retrieval"
_DATA_RESPONSE_EXTENSION_FIELD = "x-pajin-data-response"


class _OpenAPITenantSelector(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=False)

    location: Literal["body", "header", "path", "query"]
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
    )


class _OpenAPITenantRetrievalDeclaration(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=False)

    version: Literal["1"]
    tenant_selector: _OpenAPITenantSelector = Field(alias="tenantSelector")


class _OpenAPIDataResponseDeclaration(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=False)

    version: Literal["1"]
    data_classes: tuple[HTTPDataClass, ...] = Field(
        alias="dataClasses",
        min_length=1,
        max_length=_MAX_DATA_CLASSES,
    )

    @field_validator("data_classes", mode="before")
    @classmethod
    def require_canonical_data_classes(cls, value: object) -> object:
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError("OpenAPI data classes must be an array of text")
        if value != sorted(set(value)):
            raise ValueError("OpenAPI data classes must be unique and sorted")
        return tuple(value)


class HTTPAndOpenAPITenantDataSurfaceAdapter:
    """Add explicit tenant retrieval and data-response Surfaces to DISC-003C."""

    adapter_version = "1.0.0"
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
        "http-authentication",
        "http-data-response",
        "http-endpoint",
        "http-file-upload",
        "http-internal-api",
        "http-rag",
        "http-route",
        "http-tenant-retrieval",
    )
    requires_trusted_network_receipt = True

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        allowed_methods: Iterable[str] = ("GET", "HEAD", "POST"),
        max_openapi_routes: int = 200,
        max_file_uploads: int = 64,
        max_rag_boundaries: int = 32,
        max_tenant_data_boundaries: int = _DEFAULT_MAX_TENANT_DATA_BOUNDARIES,
    ) -> None:
        if (
            isinstance(max_tenant_data_boundaries, bool)
            or not isinstance(max_tenant_data_boundaries, int)
            or not 1 <= max_tenant_data_boundaries <= _DEFAULT_MAX_TENANT_DATA_BOUNDARIES
        ):
            raise ValueError("Tenant data boundary limit must be between 1 and 32")
        self._base = HTTPAndOpenAPIRAGSurfaceAdapter(
            tool=tool,
            allowed_methods=allowed_methods,
            max_openapi_routes=max_openapi_routes,
            max_file_uploads=max_file_uploads,
            max_rag_boundaries=max_rag_boundaries,
        )
        self._max_tenant_data_boundaries = max_tenant_data_boundaries
        self.tool_id = self._base.tool_id
        self.adapter_id = f"pajin.discovery.http-openapi-tenant-data:{self.tool_id}"
        self.producer_id = f"pajin.discovery.http-openapi-tenant-data.v1:{self.tool_id}"

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind inherited parsing and both exact declaration boundaries."""

        return {
            "baseHTTPAndOpenAPIRAG": self._base.stable_execution_context(),
            "tenantRetrievalExtensionField": _TENANT_RETRIEVAL_EXTENSION_FIELD,
            "dataResponseExtensionField": _DATA_RESPONSE_EXTENSION_FIELD,
            "supportedExtensionVersions": ["1"],
            "supportedTenantSelectorLocations": ["body", "header", "path", "query"],
            "maxTenantDataBoundaries": self._max_tenant_data_boundaries,
            "maxDataClasses": _MAX_DATA_CLASSES,
            "descriptionInference": False,
            "tenantValuesRetained": False,
            "retrievalQueriesRetained": False,
            "responseContentRetained": False,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        """Return inherited Surfaces plus exact tenant and data declarations."""

        candidates = self._base.extract_surfaces(request, result)
        body, content_type = self._base._base._base._base._validated_http_result(
            request,
            result,
        )
        if not _is_json_content_type(content_type):
            return candidates
        document = parse_strict_json_bytes(
            body,
            label="HTTP/OpenAPI tenant data response body",
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
        retrievals = [
            candidate.locator
            for candidate in candidates
            if isinstance(candidate.locator, HTTPRAGSurfaceLocator)
            and candidate.locator.boundary == "retrieval"
        ]
        candidates.extend(
            _tenant_data_candidates(
                document,
                routes,
                retrievals,
                max_boundaries=self._max_tenant_data_boundaries,
            )
        )
        return candidates


def _tenant_data_candidates(
    document: dict[str, object],
    routes: list[HTTPRouteSurfaceLocator],
    retrievals: list[HTTPRAGSurfaceLocator],
    *,
    max_boundaries: int,
) -> list[SurfaceCandidate]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI tenant data document paths are invalid")
    tenant_locators: dict[bytes, HTTPTenantRetrievalSurfaceLocator] = {}
    data_locators: dict[bytes, HTTPDataResponseSurfaceLocator] = {}
    for route in routes:
        path_item = paths.get(route.path_template)
        if not isinstance(path_item, dict):
            raise ValueError("OpenAPI tenant data route has no source path item")
        operation = path_item.get(route.method.lower())
        if not isinstance(operation, dict):
            raise ValueError("OpenAPI tenant data route has no source operation")
        if _TENANT_RETRIEVAL_EXTENSION_FIELD in operation:
            raw_tenant = operation[_TENANT_RETRIEVAL_EXTENSION_FIELD]
            if not isinstance(raw_tenant, dict):
                raise ValueError("OpenAPI tenant retrieval declaration must be an object")
            matching_retrievals = [item for item in retrievals if item.route == route]
            if len(matching_retrievals) != 1:
                raise ValueError(
                    "OpenAPI tenant retrieval requires one exact RAG retrieval declaration"
                )
            try:
                tenant_declaration = _OpenAPITenantRetrievalDeclaration.model_validate(raw_tenant)
                tenant_locator = http_tenant_retrieval_surface_locator(
                    retrieval=matching_retrievals[0],
                    tenant_selector=HTTPTenantSelector.model_validate(
                        tenant_declaration.tenant_selector.model_dump(mode="python")
                    ),
                )
            except (ValidationError, ValueError) as exc:
                raise ValueError("OpenAPI tenant retrieval declaration is invalid") from exc
            key = canonical_json_bytes(
                tenant_locator.model_dump(mode="json"),
                label="HTTP/OpenAPI tenant retrieval locator",
            )
            tenant_locators[key] = tenant_locator
        if _DATA_RESPONSE_EXTENSION_FIELD in operation:
            raw_data = operation[_DATA_RESPONSE_EXTENSION_FIELD]
            if not isinstance(raw_data, dict):
                raise ValueError("OpenAPI data response declaration must be an object")
            try:
                data_declaration = _OpenAPIDataResponseDeclaration.model_validate(raw_data)
                data_locator = http_data_response_surface_locator(
                    route=route,
                    data_classes=data_declaration.data_classes,
                )
            except (ValidationError, ValueError) as exc:
                raise ValueError("OpenAPI data response declaration is invalid") from exc
            key = canonical_json_bytes(
                data_locator.model_dump(mode="json"),
                label="HTTP/OpenAPI data response locator",
            )
            data_locators[key] = data_locator
        if len(tenant_locators) > max_boundaries or len(data_locators) > max_boundaries:
            raise ValueError("OpenAPI tenant data declarations exceed the limit")
    return [
        *(
            SurfaceCandidate(locator=tenant_locators[key], confidence=0.95)
            for key in sorted(tenant_locators)
        ),
        *(
            SurfaceCandidate(locator=data_locators[key], confidence=0.95)
            for key in sorted(data_locators)
        ),
    ]
