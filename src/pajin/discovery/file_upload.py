"""Bounded OpenAPI file-upload discovery over exact HTTP evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from pajin.discovery.adapters import DiscoverySurfaceKind
from pajin.discovery.admission import SurfaceCandidate
from pajin.discovery.authentication import (
    HTTPAndOpenAPIAuthenticationSurfaceAdapter,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.http import _is_json_content_type, _openapi_media_type
from pajin.discovery.models import (
    HTTPFileUploadInput,
    HTTPFileUploadSurfaceLocator,
    HTTPRouteSurfaceLocator,
    http_file_upload_surface_locator,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.tools.http import MAX_HTTP_GET_RESPONSE_BYTES, HTTPGetTool

_MAX_OPENAPI_JSON_DEPTH = 32
_MAX_OPENAPI_JSON_NODES = 4_096
_DEFAULT_MAX_FILE_UPLOADS = 64
_MAX_MULTIPART_PROPERTIES = 64
_MAX_MULTIPART_ENCODINGS = 64
_MAX_DECLARED_PART_CONTENT_TYPES = 32


@dataclass(frozen=True)
class _FileSchemaDescriptor:
    encoding: Literal["base64", "binary"]
    multiple: bool
    declared_content_types: tuple[str, ...]


class HTTPAndOpenAPIFileUploadSurfaceAdapter:
    """Add non-executable file-bearing request boundaries to Auth and HTTP Surfaces."""

    adapter_version = "1.0.0"
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
        "http-authentication",
        "http-endpoint",
        "http-file-upload",
        "http-route",
    )
    requires_trusted_network_receipt = True

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        allowed_methods: Iterable[str] = ("GET", "HEAD", "POST"),
        max_openapi_routes: int = 200,
        max_file_uploads: int = _DEFAULT_MAX_FILE_UPLOADS,
    ) -> None:
        if (
            isinstance(max_file_uploads, bool)
            or not isinstance(max_file_uploads, int)
            or not 1 <= max_file_uploads <= _DEFAULT_MAX_FILE_UPLOADS
        ):
            raise ValueError("OpenAPI file-upload limit must be between 1 and 64")
        self._base = HTTPAndOpenAPIAuthenticationSurfaceAdapter(
            tool=tool,
            allowed_methods=allowed_methods,
            max_openapi_routes=max_openapi_routes,
        )
        self._max_file_uploads = max_file_uploads
        self.tool_id = self._base.tool_id
        self.adapter_id = f"pajin.discovery.http-openapi-file-upload:{self.tool_id}"
        self.producer_id = f"pajin.discovery.http-openapi-file-upload.v1:{self.tool_id}"

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind the inherited parser and every file-upload interpretation boundary."""

        return {
            "baseHTTPAndOpenAPIAuthentication": self._base.stable_execution_context(),
            "maxFileUploads": self._max_file_uploads,
            "maxMultipartProperties": _MAX_MULTIPART_PROPERTIES,
            "maxMultipartEncodings": _MAX_MULTIPART_ENCODINGS,
            "maxDeclaredPartContentTypes": _MAX_DECLARED_PART_CONTENT_TYPES,
            "supportedFileEncodings": ["base64", "binary"],
            "externalRefResolution": False,
            "fileBytesRetained": False,
            "fileDestinationsRetained": False,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        """Return inherited Surfaces plus declared file-bearing request boundaries."""

        candidates = self._base.extract_surfaces(request, result)
        body, content_type = self._base._base._validated_http_result(request, result)
        if not _is_json_content_type(content_type):
            return candidates
        document = parse_strict_json_bytes(
            body,
            label="HTTP/OpenAPI file-upload response body",
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
            _file_upload_candidates(
                document,
                routes,
                max_file_uploads=self._max_file_uploads,
            )
        )
        return candidates


def _file_upload_candidates(
    document: dict[str, object],
    routes: list[HTTPRouteSurfaceLocator],
    *,
    max_file_uploads: int,
) -> list[SurfaceCandidate]:
    paths = document.get("paths")
    version = document.get("openapi")
    if not isinstance(paths, dict) or not isinstance(version, str):
        raise ValueError("OpenAPI file-upload document identity is invalid")
    locators: dict[bytes, HTTPFileUploadSurfaceLocator] = {}
    upload_count = 0
    for route in routes:
        path_item = paths.get(route.path_template)
        if not isinstance(path_item, dict):
            raise ValueError("OpenAPI file-upload route has no source path item")
        operation = path_item.get(route.method.lower())
        if not isinstance(operation, dict):
            raise ValueError("OpenAPI file-upload route has no source operation")
        request_body_required, uploads = _operation_file_upload_inputs(
            operation,
            version=version,
        )
        if not uploads:
            continue
        upload_count += len(uploads)
        if upload_count > max_file_uploads:
            raise ValueError("OpenAPI file-upload declarations exceed the limit")
        locator = http_file_upload_surface_locator(
            route=route,
            request_body_required=request_body_required,
            uploads=uploads,
        )
        key = canonical_json_bytes(
            locator.model_dump(mode="json"),
            label="HTTP/OpenAPI file-upload locator",
        )
        locators[key] = locator
    return [
        SurfaceCandidate(locator=locators[key], confidence=0.95)
        for key in sorted(locators)
    ]


def _operation_file_upload_inputs(
    operation: dict[str, object],
    *,
    version: str,
) -> tuple[bool, tuple[HTTPFileUploadInput, ...]]:
    request_body = operation.get("requestBody")
    if request_body is None:
        return False, ()
    if not isinstance(request_body, dict):
        raise ValueError("OpenAPI file-upload requestBody is invalid")
    if "$ref" in request_body:
        return False, ()
    raw_required = request_body.get("required", False)
    if not isinstance(raw_required, bool):
        raise ValueError("OpenAPI requestBody required flag must be a boolean")
    content = request_body.get("content")
    if content is None:
        return raw_required, ()
    if not isinstance(content, dict):
        raise ValueError("OpenAPI file-upload content is invalid")
    uploads: list[HTTPFileUploadInput] = []
    for raw_content_type, media_entry in content.items():
        request_content_type = _openapi_media_type(raw_content_type)
        if not isinstance(media_entry, dict):
            raise ValueError("OpenAPI file-upload media entry is invalid")
        if request_content_type == "multipart/form-data":
            uploads.extend(
                _multipart_file_upload_inputs(
                    media_entry,
                    request_content_type=request_content_type,
                    version=version,
                )
            )
            continue
        descriptor = _raw_file_schema_descriptor(media_entry, version=version)
        if descriptor is None:
            continue
        uploads.append(
            HTTPFileUploadInput(
                request_content_type=request_content_type,
                field_name=None,
                required=raw_required,
                multiple=False,
                encoding=descriptor.encoding,
                declared_content_types=descriptor.declared_content_types,
            )
        )
    uploads.sort(key=_upload_sort_key)
    return raw_required, tuple(uploads)


def _multipart_file_upload_inputs(
    media_entry: dict[str, object],
    *,
    request_content_type: str,
    version: str,
) -> tuple[HTTPFileUploadInput, ...]:
    schema = media_entry.get("schema")
    if schema is None:
        return ()
    if not isinstance(schema, dict):
        raise ValueError("OpenAPI multipart schema is invalid")
    if "$ref" in schema:
        return ()
    schema_type = schema.get("type")
    if schema_type not in {None, "object"}:
        raise ValueError("OpenAPI multipart schema must be an object")
    properties = schema.get("properties")
    if properties is None:
        return ()
    if (
        not isinstance(properties, dict)
        or len(properties) > _MAX_MULTIPART_PROPERTIES
    ):
        raise ValueError("OpenAPI multipart properties are invalid or exceed the limit")
    required = _required_property_names(schema.get("required"), properties)
    encodings = _multipart_encodings(media_entry.get("encoding"), properties)
    uploads: list[HTTPFileUploadInput] = []
    for field_name, property_schema in properties.items():
        if not isinstance(field_name, str) or not isinstance(property_schema, dict):
            raise ValueError("OpenAPI multipart property is invalid")
        descriptor = _file_schema_descriptor(
            property_schema,
            version=version,
            allow_array=True,
        )
        if descriptor is None:
            continue
        declared_content_types = _multipart_declared_content_types(
            encodings.get(field_name),
            fallback=descriptor.declared_content_types,
        )
        uploads.append(
            HTTPFileUploadInput(
                request_content_type=request_content_type,
                field_name=field_name,
                required=field_name in required,
                multiple=descriptor.multiple,
                encoding=descriptor.encoding,
                declared_content_types=declared_content_types,
            )
        )
    uploads.sort(key=_upload_sort_key)
    return tuple(uploads)


def _raw_file_schema_descriptor(
    media_entry: dict[str, object],
    *,
    version: str,
) -> _FileSchemaDescriptor | None:
    schema = media_entry.get("schema")
    if schema is None:
        return None
    if not isinstance(schema, dict):
        raise ValueError("OpenAPI raw file schema is invalid")
    descriptor = _file_schema_descriptor(
        schema,
        version=version,
        allow_array=False,
    )
    return descriptor


def _file_schema_descriptor(
    schema: dict[str, object],
    *,
    version: str,
    allow_array: bool,
) -> _FileSchemaDescriptor | None:
    if "$ref" in schema:
        return None
    schema_type = schema.get("type")
    if schema_type == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            raise ValueError("OpenAPI file array items are invalid")
        descriptor = _file_schema_descriptor(
            items,
            version=version,
            allow_array=False,
        )
        if descriptor is None:
            return None
        if not allow_array:
            raise ValueError("OpenAPI raw file upload arrays are unsupported")
        return _FileSchemaDescriptor(
            encoding=descriptor.encoding,
            multiple=True,
            declared_content_types=descriptor.declared_content_types,
        )
    if schema_type != "string":
        return None
    return _string_file_schema_descriptor(schema, version=version)


def _string_file_schema_descriptor(
    schema: dict[str, object],
    *,
    version: str,
) -> _FileSchemaDescriptor | None:
    raw_format = schema.get("format")
    raw_content_encoding = schema.get("contentEncoding")
    if raw_format is not None and not isinstance(raw_format, str):
        raise ValueError("OpenAPI file format is invalid")
    if raw_content_encoding is not None and not isinstance(
        raw_content_encoding,
        str,
    ):
        raise ValueError("OpenAPI file contentEncoding is invalid")
    encoding: Literal["base64", "binary"] | None = None
    if raw_format == "binary":
        encoding = "binary"
    elif raw_format == "byte":
        encoding = "base64"
    if raw_content_encoding is not None:
        if not version.startswith("3.1."):
            raise ValueError("OpenAPI contentEncoding requires version 3.1")
        if raw_content_encoding != "base64":
            raise ValueError("OpenAPI file contentEncoding is unsupported")
        if encoding == "binary":
            raise ValueError("OpenAPI file encoding declarations contradict")
        encoding = "base64"
    if encoding is None:
        return None
    return _FileSchemaDescriptor(
        encoding=encoding,
        multiple=False,
        declared_content_types=_schema_declared_content_types(
            schema.get("contentMediaType"),
            version=version,
        ),
    )


def _schema_declared_content_types(
    value: object,
    *,
    version: str,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not version.startswith("3.1."):
        raise ValueError("OpenAPI contentMediaType requires version 3.1")
    media_type = _openapi_media_type(value)
    if "*" in media_type:
        raise ValueError("OpenAPI file contentMediaType cannot be a wildcard")
    return (media_type,)


def _required_property_names(
    value: object,
    properties: dict[object, object],
) -> frozenset[str]:
    if value is None:
        return frozenset()
    if (
        not isinstance(value, list)
        or len(value) > _MAX_MULTIPART_PROPERTIES
        or any(not isinstance(item, str) for item in value)
    ):
        raise ValueError("OpenAPI multipart required properties are invalid")
    if len(value) != len(set(value)):
        raise ValueError("OpenAPI multipart required properties contain a duplicate")
    required = frozenset(value)
    if not required <= set(properties):
        raise ValueError("OpenAPI multipart required property is unknown")
    return required


def _multipart_encodings(
    value: object,
    properties: dict[object, object],
) -> dict[str, dict[str, object]]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > _MAX_MULTIPART_ENCODINGS:
        raise ValueError("OpenAPI multipart encodings are invalid or exceed the limit")
    encodings: dict[str, dict[str, object]] = {}
    for field_name, encoding in value.items():
        if (
            not isinstance(field_name, str)
            or field_name not in properties
            or not isinstance(encoding, dict)
        ):
            raise ValueError("OpenAPI multipart encoding entry is invalid")
        encodings[field_name] = encoding
    return encodings


def _multipart_declared_content_types(
    encoding: dict[str, object] | None,
    *,
    fallback: tuple[str, ...],
) -> tuple[str, ...]:
    if encoding is None or "contentType" not in encoding:
        return fallback
    raw_value = encoding["contentType"]
    if not isinstance(raw_value, str) or len(raw_value) > 2_000:
        raise ValueError("OpenAPI multipart encoding contentType is invalid")
    values = raw_value.split(",")
    if not values or len(values) > _MAX_DECLARED_PART_CONTENT_TYPES:
        raise ValueError(
            "OpenAPI multipart encoding content types exceed the limit"
        )
    normalized = tuple(
        sorted({_openapi_media_type(item.strip()) for item in values})
    )
    if len(normalized) != len(values):
        raise ValueError(
            "OpenAPI multipart encoding content types contain a duplicate"
        )
    return normalized


def _upload_sort_key(
    upload: HTTPFileUploadInput,
) -> tuple[str, str, str, bool, bool, tuple[str, ...]]:
    return (
        upload.request_content_type,
        upload.field_name or "",
        upload.encoding,
        upload.multiple,
        upload.required,
        upload.declared_content_types,
    )
