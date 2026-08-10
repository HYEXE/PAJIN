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
    HTTPAndOpenAPIFileUploadSurfaceAdapter,
    HTTPAuthenticationSurfaceLocator,
    HTTPFileUploadInput,
    HTTPFileUploadSurfaceLocator,
    http_file_upload_surface_locator,
    http_route_surface_locator,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.tools.base import ToolRegistry
from pajin.tools.http import HTTPGetTool

NOW = datetime(2026, 7, 29, 2, 0, tzinfo=UTC)
TARGET = "https://staging.example.invalid/openapi.json"


def _request() -> ToolRequest:
    return ToolRequest(
        request_id="http_file_upload_1",
        agent_id="recon-specialist:file-upload",
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
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                }
            }
        },
        "security": [{"BearerAuth": []}],
        "paths": {
            "/documents": {
                "post": {
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
                                        },
                                        "attachments": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                                "format": "byte",
                                                "contentMediaType": "application/pdf",
                                            },
                                        },
                                        "note": {"type": "string"},
                                    },
                                },
                                "encoding": {
                                    "file": {
                                        "contentType": "image/png, image/jpeg",
                                    }
                                },
                            }
                        },
                    },
                    "responses": {"202": {"description": "accepted"}},
                }
            },
            "/archive": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/zip": {
                                "schema": {
                                    "type": "string",
                                    "format": "binary",
                                }
                            }
                        }
                    },
                    "responses": {"204": {"description": "stored"}},
                }
            },
            "/metadata": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "description": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }


def _adapter(
    *,
    max_file_uploads: int = 64,
) -> HTTPAndOpenAPIFileUploadSurfaceAdapter:
    return HTTPAndOpenAPIFileUploadSurfaceAdapter(
        tool=HTTPGetTool(),
        allowed_methods=("GET", "POST"),
        max_file_uploads=max_file_uploads,
    )


def _file_locators(candidates: list[object]) -> list[HTTPFileUploadSurfaceLocator]:
    return [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPFileUploadSurfaceLocator)
    ]


def test_file_upload_adapter_preserves_inherited_surfaces_and_upload_shape() -> None:
    candidates = _adapter().extract_surfaces(_request(), _result(_document()))

    assert any(
        isinstance(candidate.locator, HTTPAuthenticationSurfaceLocator)
        for candidate in candidates
    )
    locators = _file_locators(candidates)
    assert [locator.route.path_template for locator in locators] == [
        "/archive",
        "/documents",
    ]

    raw, multipart = locators
    assert raw.request_body_required is False
    assert raw.uploads == (
        HTTPFileUploadInput(
            request_content_type="application/zip",
            field_name=None,
            required=False,
            multiple=False,
            encoding="binary",
        ),
    )

    assert multipart.request_body_required is True
    assert [
        (
            upload.field_name,
            upload.required,
            upload.multiple,
            upload.encoding,
            upload.declared_content_types,
        )
        for upload in multipart.uploads
    ] == [
        ("attachments", False, True, "base64", ("application/pdf",)),
        ("file", True, False, "binary", ("image/jpeg", "image/png")),
    ]
    assert all(
        locator.route.path_template != "/metadata" for locator in locators
    )


def test_file_upload_adapter_is_deterministic_across_object_and_media_order() -> None:
    document = _document()
    reversed_document = deepcopy(document)
    paths = reversed_document["paths"]
    assert isinstance(paths, dict)
    reversed_document["paths"] = dict(reversed(list(paths.items())))
    documents = paths["/documents"]
    assert isinstance(documents, dict)
    post = documents["post"]
    assert isinstance(post, dict)
    request_body = post["requestBody"]
    assert isinstance(request_body, dict)
    content = request_body["content"]
    assert isinstance(content, dict)
    multipart = content["multipart/form-data"]
    assert isinstance(multipart, dict)
    schema = multipart["schema"]
    assert isinstance(schema, dict)
    properties = schema["properties"]
    assert isinstance(properties, dict)
    schema["properties"] = dict(reversed(list(properties.items())))
    encoding = multipart["encoding"]
    assert isinstance(encoding, dict)
    file_encoding = encoding["file"]
    assert isinstance(file_encoding, dict)
    file_encoding["contentType"] = "image/jpeg, image/png"

    first = _adapter().extract_surfaces(_request(), _result(document))
    second = _adapter().extract_surfaces(_request(), _result(reversed_document))

    assert [
        candidate.locator.model_dump(mode="json") for candidate in first
    ] == [
        candidate.locator.model_dump(mode="json") for candidate in second
    ]


def test_file_upload_adapter_does_not_resolve_referenced_request_schemas() -> None:
    document = _document()
    paths = document["paths"]
    assert isinstance(paths, dict)
    documents = paths["/documents"]
    assert isinstance(documents, dict)
    post = documents["post"]
    assert isinstance(post, dict)
    post["requestBody"] = {"$ref": "#/components/requestBodies/Upload"}

    candidates = _adapter().extract_surfaces(_request(), _result(document))

    assert all(
        locator.route.path_template != "/documents"
        for locator in _file_locators(candidates)
    )

    second = _document()
    paths = second["paths"]
    assert isinstance(paths, dict)
    documents = paths["/documents"]
    assert isinstance(documents, dict)
    post = documents["post"]
    assert isinstance(post, dict)
    request_body = post["requestBody"]
    assert isinstance(request_body, dict)
    content = request_body["content"]
    assert isinstance(content, dict)
    multipart = content["multipart/form-data"]
    assert isinstance(multipart, dict)
    multipart["schema"] = {"$ref": "#/components/schemas/Upload"}

    candidates = _adapter().extract_surfaces(_request(), _result(second))
    assert all(
        locator.route.path_template != "/documents"
        for locator in _file_locators(candidates)
    )


def test_file_upload_adapter_supports_openapi_31_base64_content_encoding() -> None:
    document = _document()
    paths = document["paths"]
    assert isinstance(paths, dict)
    archive = paths["/archive"]
    assert isinstance(archive, dict)
    post = archive["post"]
    assert isinstance(post, dict)
    request_body = post["requestBody"]
    assert isinstance(request_body, dict)
    content = request_body["content"]
    assert isinstance(content, dict)
    content["application/zip"] = {
        "schema": {
            "type": "string",
            "contentEncoding": "base64",
            "contentMediaType": "application/zip",
        }
    }

    locator = next(
        item
        for item in _file_locators(
            _adapter().extract_surfaces(_request(), _result(document))
        )
        if item.route.path_template == "/archive"
    )

    assert locator.uploads[0].encoding == "base64"
    assert locator.uploads[0].declared_content_types == ("application/zip",)


def _documents_multipart(document: dict[str, object]) -> dict[str, object]:
    paths = document["paths"]
    assert isinstance(paths, dict)
    documents = paths["/documents"]
    assert isinstance(documents, dict)
    post = documents["post"]
    assert isinstance(post, dict)
    request_body = post["requestBody"]
    assert isinstance(request_body, dict)
    content = request_body["content"]
    assert isinstance(content, dict)
    multipart = content["multipart/form-data"]
    assert isinstance(multipart, dict)
    return multipart


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda document: _documents_multipart(document).__setitem__(
                "encoding",
                {"unknown": {"contentType": "image/png"}},
            ),
            "encoding entry",
        ),
        (
            lambda document: _documents_multipart(document)["schema"].__setitem__(  # type: ignore[union-attr]
                "required",
                ["missing"],
            ),
            "required property is unknown",
        ),
        (
            lambda document: _documents_multipart(document)["encoding"]["file"].__setitem__(  # type: ignore[index,union-attr]
                "contentType",
                "image/png, image/png",
            ),
            "contain a duplicate",
        ),
        (
            lambda document: _documents_multipart(document)["schema"]["properties"].__setitem__(  # type: ignore[index,union-attr]
                "file name",
                {"type": "string", "format": "binary"},
            ),
            "field_name",
        ),
    ],
)
def test_file_upload_adapter_rejects_malformed_multipart_authority(
    mutator: object,
    message: str,
) -> None:
    document = _document()
    assert callable(mutator)
    mutator(document)

    with pytest.raises((ValidationError, ValueError), match=message):
        _adapter().extract_surfaces(_request(), _result(document))


def test_file_upload_adapter_rejects_ambiguous_raw_encodings_and_limits() -> None:
    document = _document()
    paths = document["paths"]
    assert isinstance(paths, dict)
    archive = paths["/archive"]
    assert isinstance(archive, dict)
    post = archive["post"]
    assert isinstance(post, dict)
    request_body = post["requestBody"]
    assert isinstance(request_body, dict)
    content = request_body["content"]
    assert isinstance(content, dict)
    content["application/zip"] = {
        "schema": {
            "type": "array",
            "items": {"type": "string", "format": "binary"},
        }
    }
    with pytest.raises(ValueError, match="raw file upload arrays"):
        _adapter().extract_surfaces(_request(), _result(document))

    contradictory = _document()
    contradictory["openapi"] = "3.1.0"
    multipart = _documents_multipart(contradictory)
    schema = multipart["schema"]
    assert isinstance(schema, dict)
    properties = schema["properties"]
    assert isinstance(properties, dict)
    file_schema = properties["file"]
    assert isinstance(file_schema, dict)
    file_schema["contentEncoding"] = "base64"
    with pytest.raises(ValueError, match="contradict"):
        _adapter().extract_surfaces(_request(), _result(contradictory))

    old_version = _document()
    old_version["openapi"] = "3.0.3"
    multipart = _documents_multipart(old_version)
    schema = multipart["schema"]
    assert isinstance(schema, dict)
    properties = schema["properties"]
    assert isinstance(properties, dict)
    file_schema = properties["file"]
    assert isinstance(file_schema, dict)
    file_schema.pop("format")
    file_schema["contentEncoding"] = "base64"
    with pytest.raises(ValueError, match=r"requires version 3\.1"):
        _adapter().extract_surfaces(_request(), _result(old_version))

    with pytest.raises(ValueError, match="exceed the limit"):
        _adapter(max_file_uploads=1).extract_surfaces(
            _request(),
            _result(_document()),
        )


def test_file_upload_locator_rejects_inconsistent_or_noncanonical_contracts() -> None:
    route = http_route_surface_locator(
        base_url="https://staging.example.invalid/api",
        path_template="/documents",
        method="POST",
        request_content_types=("application/zip", "multipart/form-data"),
    )
    raw = HTTPFileUploadInput(
        request_content_type="application/zip",
        required=True,
        encoding="binary",
    )
    multipart = HTTPFileUploadInput(
        request_content_type="multipart/form-data",
        field_name="file",
        required=True,
        encoding="binary",
    )

    locator = http_file_upload_surface_locator(
        route=route,
        request_body_required=True,
        uploads=(raw, multipart),
    )
    assert locator.route is not route
    assert locator.uploads[0] is not raw

    with pytest.raises(ValidationError, match="declared by the bound HTTP route"):
        http_file_upload_surface_locator(
            route=route,
            request_body_required=True,
            uploads=(
                HTTPFileUploadInput(
                    request_content_type="image/png",
                    required=True,
                    encoding="binary",
                ),
            ),
        )
    with pytest.raises(ValidationError, match="must match"):
        http_file_upload_surface_locator(
            route=route,
            request_body_required=False,
            uploads=(raw,),
        )
    with pytest.raises(ValidationError, match="unique and sorted"):
        http_file_upload_surface_locator(
            route=route,
            request_body_required=True,
            uploads=(multipart, raw),
        )
    with pytest.raises(ValidationError, match="identities"):
        http_file_upload_surface_locator(
            route=route,
            request_body_required=True,
            uploads=(
                multipart,
                HTTPFileUploadInput(
                    request_content_type="multipart/form-data",
                    field_name="file",
                    required=True,
                    encoding="base64",
                ),
            ),
        )


def test_file_upload_adapter_registry_binds_exact_domain_contract() -> None:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIFileUploadSurfaceAdapter(
        tool=tool,
        allowed_methods=("POST", "GET"),
        max_openapi_routes=25,
        max_file_uploads=12,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])

    definition = registry.definitions()[0]

    assert definition.supported_surface_kinds == (
        "http-authentication",
        "http-endpoint",
        "http-file-upload",
        "http-internal-api",
        "http-route",
    )
    assert definition.requires_trusted_network_receipt is True
    assert registry.resolve(definition.reference()).adapter is adapter
    context = adapter.stable_execution_context()
    assert context["maxFileUploads"] == 12
    assert context["externalRefResolution"] is False
    assert context["fileBytesRetained"] is False
