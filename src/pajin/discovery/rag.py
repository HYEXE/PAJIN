"""Bounded explicit RAG boundary discovery over exact HTTP evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, ValidationError, field_validator

from pajin.discovery.adapters import DiscoverySurfaceKind
from pajin.discovery.admission import SurfaceCandidate
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.file_upload import HTTPAndOpenAPIFileUploadSurfaceAdapter
from pajin.discovery.http import _is_json_content_type
from pajin.discovery.models import (
    HTTPRAGSurfaceLocator,
    HTTPRouteSurfaceLocator,
    http_rag_surface_locator,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.tools.http import MAX_HTTP_GET_RESPONSE_BYTES, HTTPGetTool

_MAX_OPENAPI_JSON_DEPTH = 32
_MAX_OPENAPI_JSON_NODES = 4_096
_DEFAULT_MAX_RAG_BOUNDARIES = 32
_MAX_RAG_IDENTIFIERS = 16
_RAG_EXTENSION_FIELD = "x-pajin-rag"
_RAG_DECLARATION_FIELDS = frozenset(
    {"version", "boundary", "corpusIds", "indexIds"}
)
_PortableIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
]


class _OpenAPIRAGDeclaration(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=False)

    version: Literal["1"]
    boundary: Literal["corpus-ingest", "index-management", "retrieval"]
    corpus_ids: tuple[_PortableIdentifier, ...] = Field(
        default=(),
        alias="corpusIds",
        max_length=_MAX_RAG_IDENTIFIERS,
    )
    index_ids: tuple[_PortableIdentifier, ...] = Field(
        default=(),
        alias="indexIds",
        max_length=_MAX_RAG_IDENTIFIERS,
    )

    @field_validator("corpus_ids", "index_ids", mode="before")
    @classmethod
    def require_canonical_identifiers(cls, value: object) -> object:
        if not isinstance(value, list):
            raise ValueError("OpenAPI RAG identifiers must be arrays")
        if any(not isinstance(item, str) for item in value):
            raise ValueError("OpenAPI RAG identifier must be text")
        if value != sorted(set(value)):
            raise ValueError("OpenAPI RAG identifiers must be unique and sorted")
        return tuple(value)


class HTTPAndOpenAPIRAGSurfaceAdapter:
    """Add explicit non-executable RAG boundaries to File, Auth, and HTTP Surfaces."""

    adapter_version = "1.0.0"
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
        "http-authentication",
        "http-endpoint",
        "http-file-upload",
        "http-rag",
        "http-route",
    )
    requires_trusted_network_receipt = True

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        allowed_methods: Iterable[str] = ("GET", "HEAD", "POST"),
        max_openapi_routes: int = 200,
        max_file_uploads: int = 64,
        max_rag_boundaries: int = _DEFAULT_MAX_RAG_BOUNDARIES,
    ) -> None:
        if (
            isinstance(max_rag_boundaries, bool)
            or not isinstance(max_rag_boundaries, int)
            or not 1 <= max_rag_boundaries <= _DEFAULT_MAX_RAG_BOUNDARIES
        ):
            raise ValueError("OpenAPI RAG boundary limit must be between 1 and 32")
        self._base = HTTPAndOpenAPIFileUploadSurfaceAdapter(
            tool=tool,
            allowed_methods=allowed_methods,
            max_openapi_routes=max_openapi_routes,
            max_file_uploads=max_file_uploads,
        )
        self._max_rag_boundaries = max_rag_boundaries
        self.tool_id = self._base.tool_id
        self.adapter_id = f"pajin.discovery.http-openapi-rag:{self.tool_id}"
        self.producer_id = f"pajin.discovery.http-openapi-rag.v1:{self.tool_id}"

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind the inherited parser and explicit RAG interpretation boundary."""

        return {
            "baseHTTPAndOpenAPIFileUpload": self._base.stable_execution_context(),
            "extensionField": _RAG_EXTENSION_FIELD,
            "supportedExtensionVersions": ["1"],
            "supportedRAGBoundaries": [
                "corpus-ingest",
                "index-management",
                "retrieval",
            ],
            "maxRAGBoundaries": self._max_rag_boundaries,
            "maxCorpusIdentifiers": _MAX_RAG_IDENTIFIERS,
            "maxIndexIdentifiers": _MAX_RAG_IDENTIFIERS,
            "descriptionInference": False,
            "externalRefResolution": False,
            "corpusContentRetained": False,
            "retrievalQueriesRetained": False,
            "retrievedContentRetained": False,
            "embeddingsRetained": False,
            "vectorValuesRetained": False,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        """Return inherited Surfaces plus explicitly declared RAG boundaries."""

        candidates = self._base.extract_surfaces(request, result)
        body, content_type = self._base._base._base._validated_http_result(
            request,
            result,
        )
        if not _is_json_content_type(content_type):
            return candidates
        document = parse_strict_json_bytes(
            body,
            label="HTTP/OpenAPI RAG response body",
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
        candidates.extend(
            _rag_candidates(
                document,
                routes,
                max_rag_boundaries=self._max_rag_boundaries,
            )
        )
        return candidates


def _rag_candidates(
    document: dict[str, object],
    routes: list[HTTPRouteSurfaceLocator],
    *,
    max_rag_boundaries: int,
) -> list[SurfaceCandidate]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI RAG document paths are invalid")
    locators: dict[bytes, HTTPRAGSurfaceLocator] = {}
    for route in routes:
        path_item = paths.get(route.path_template)
        if not isinstance(path_item, dict):
            raise ValueError("OpenAPI RAG route has no source path item")
        operation = path_item.get(route.method.lower())
        if not isinstance(operation, dict):
            raise ValueError("OpenAPI RAG route has no source operation")
        if _RAG_EXTENSION_FIELD not in operation:
            continue
        raw_declaration = operation[_RAG_EXTENSION_FIELD]
        if not isinstance(raw_declaration, dict):
            raise ValueError("OpenAPI RAG declaration must be an object")
        if any(
            not isinstance(field, str) or field not in _RAG_DECLARATION_FIELDS
            for field in raw_declaration
        ):
            raise ValueError("OpenAPI RAG declaration contains an unknown field")
        try:
            declaration = _OpenAPIRAGDeclaration.model_validate(raw_declaration)
            locator = http_rag_surface_locator(
                route=route,
                boundary=declaration.boundary,
                corpus_ids=declaration.corpus_ids,
                index_ids=declaration.index_ids,
            )
        except (ValidationError, ValueError) as exc:
            raise ValueError("OpenAPI RAG declaration is invalid") from exc
        key = canonical_json_bytes(
            locator.model_dump(mode="json"),
            label="HTTP/OpenAPI RAG locator",
        )
        locators[key] = locator
        if len(locators) > max_rag_boundaries:
            raise ValueError("OpenAPI RAG declarations exceed the limit")
    return [
        SurfaceCandidate(locator=locators[key], confidence=0.95)
        for key in sorted(locators)
    ]
