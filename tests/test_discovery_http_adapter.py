from __future__ import annotations

import json
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIAuthenticationSurfaceAdapter,
    HTTPAndOpenAPIFileUploadSurfaceAdapter,
    HTTPAndOpenAPIRAGSurfaceAdapter,
    HTTPAndOpenAPISurfaceAdapter,
    HTTPAuthenticationSurfaceLocator,
    HTTPFileUploadSurfaceLocator,
    HTTPInternalAPISurfaceLocator,
    HTTPRAGSurfaceLocator,
    HTTPRouteSurfaceLocator,
    SurfaceAdmissionError,
    TrustedSurfaceProducer,
    http_route_scope_url,
    http_route_surface_locator,
    publish_surface_projection,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult
from pajin.policy.engine import PolicyDecision
from pajin.runtime.store import RunStore, load_verified_run_events
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.base import (
    EGRESS_HTTP_RECEIPT_VERSION,
    ToolRegistry,
    audit_http_target,
    http_target_sha256,
)
from pajin.tools.http import HTTPGetTool

NOW = datetime(2026, 7, 28, 5, 0, tzinfo=UTC)
TARGET = "https://staging.example.invalid/api/openapi.json"
EVIDENCE_REFERENCE = "evidence/http_openapi_1.json"


def _request(*, target: str = TARGET) -> ToolRequest:
    return ToolRequest(
        request_id="http_openapi_1",
        agent_id="recon-specialist:test",
        tool_id=HTTPGetTool.spec.tool_id,
        target=target,
        method="GET",
    )


def _result(
    body: bytes,
    *,
    request: ToolRequest | None = None,
    content_type: str | None = "application/json",
) -> ToolResult:
    request = request or _request()
    data: dict[str, object] = {
        "target": request.target,
        "status": 200,
        "bodyPreview": body.decode("utf-8", errors="replace"),
        "bodySha256": sha256(body).hexdigest(),
        "responseBodyBase64": b64encode(body).decode("ascii"),
    }
    if content_type is not None:
        data["contentType"] = content_type
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        data=data,
    )


def _worker_result(request: ToolRequest, body: bytes) -> WorkerResult:
    return WorkerResult(
        execution_id="exec_http_openapi_1",
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout="{}",
        network_log="\n".join(
            [
                json.dumps({"event": "ready", "port": 8080}),
                json.dumps(
                    {
                        "event": "allow",
                        "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
                        "sequence": 1,
                        "method": "GET",
                        "target": audit_http_target(request.target),
                        "targetSha256": http_target_sha256(request.target),
                        "address": "203.0.113.10",
                        "status": 200,
                        "responseBodySha256": sha256(body).hexdigest(),
                    }
                ),
            ]
        ),
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
    )


def _openapi_document() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/users/{user_id}": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/problem+json": {},
                            "application/json": {},
                        }
                    },
                    "responses": {
                        "201": {"content": {"application/json": {}}},
                    },
                },
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "text/plain": {},
                                "application/json": {},
                            }
                        }
                    }
                },
            },
            "/ignored-delete": {
                "delete": {
                    "responses": {"204": {"description": "deleted"}},
                }
            },
        },
    }


def _adapter(
    *,
    allowed_methods: tuple[str, ...] = ("GET", "POST"),
    max_openapi_routes: int = 200,
) -> HTTPAndOpenAPISurfaceAdapter:
    return HTTPAndOpenAPISurfaceAdapter(
        tool=HTTPGetTool(),
        allowed_methods=allowed_methods,
        max_openapi_routes=max_openapi_routes,
    )


def test_http_openapi_adapter_emits_endpoint_and_canonical_routes() -> None:
    body = json.dumps(_openapi_document()).encode("utf-8")

    candidates = _adapter().extract_surfaces(_request(), _result(body))

    assert len(candidates) == 3
    assert candidates[0].locator.kind == "http-endpoint"
    assert candidates[0].locator.url == TARGET
    routes = [candidate.locator for candidate in candidates[1:]]
    assert all(isinstance(route, HTTPRouteSurfaceLocator) for route in routes)
    assert [route.method for route in routes] == ["GET", "POST"]
    get_route, post_route = routes
    assert get_route.base_url == "https://staging.example.invalid/api"
    assert get_route.path_template == "/users/{user_id}"
    assert get_route.request_content_types == ()
    assert get_route.response_content_types == ("application/json", "text/plain")
    assert post_route.request_content_types == (
        "application/json",
        "application/problem+json",
    )
    assert post_route.response_content_types == ("application/json",)
    assert http_route_scope_url(get_route) == (
        "https://staging.example.invalid/api/users/pajin-route-parameter"
    )


def test_http_route_locator_rejects_noncanonical_templates_and_content_types() -> None:
    with pytest.raises(ValueError, match="encoded slash"):
        http_route_surface_locator(
            base_url="https://staging.example.invalid/api",
            path_template="/users/%2Fadmin",
            method="GET",
        )
    with pytest.raises(ValueError, match="empty segment"):
        http_route_surface_locator(
            base_url="https://staging.example.invalid/api",
            path_template="/users//profile",
            method="GET",
        )
    with pytest.raises(ValueError, match="unique and sorted"):
        http_route_surface_locator(
            base_url="https://staging.example.invalid/api",
            path_template="/users",
            method="POST",
            request_content_types=("text/plain", "application/json"),
        )

    wildcard = http_route_surface_locator(
        base_url="https://staging.example.invalid/api/",
        path_template="/users/{user_id}",
        method="get",
        response_content_types=("*/*",),
    )
    assert wildcard.base_url == "https://staging.example.invalid/api"
    assert wildcard.method == "GET"
    assert wildcard.response_content_types == ("*/*",)


def test_openapi_adapter_admits_only_explicit_internal_api_declaration() -> None:
    document = _openapi_document()
    operation = document["paths"]["/users/{user_id}"]["get"]  # type: ignore[index]
    operation["x-pajin-internal-api"] = True  # type: ignore[index]

    candidates = _adapter().extract_surfaces(
        _request(),
        _result(json.dumps(document).encode("utf-8")),
    )
    internal = [
        candidate.locator
        for candidate in candidates
        if isinstance(candidate.locator, HTTPInternalAPISurfaceLocator)
    ]

    assert len(internal) == 1
    assert internal[0].route.path_template == "/users/{user_id}"
    assert internal[0].route.method == "GET"
    assert internal[0].declaration == "openapi-x-pajin-internal-api"


def test_openapi_adapter_rejects_non_boolean_internal_api_declaration() -> None:
    document = _openapi_document()
    operation = document["paths"]["/users/{user_id}"]["get"]  # type: ignore[index]
    operation["x-pajin-internal-api"] = "true"  # type: ignore[index]

    with pytest.raises(ValueError, match="must be a boolean"):
        _adapter().extract_surfaces(
            _request(),
            _result(json.dumps(document).encode("utf-8")),
        )


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("text/html; charset=utf-8", b"<html></html>"),
        ("application/json", b'{"items":[]}'),
        (None, b"opaque"),
    ],
)
def test_http_adapter_preserves_non_openapi_response_as_endpoint_only(
    content_type: str | None,
    body: bytes,
) -> None:
    candidates = _adapter().extract_surfaces(
        _request(),
        _result(body, content_type=content_type),
    )

    assert len(candidates) == 1
    assert candidates[0].locator.kind == "http-endpoint"


def test_openapi_route_output_is_independent_of_input_map_order() -> None:
    first = _openapi_document()
    second = {
        "paths": {
            key: dict(reversed(list(value.items())))
            for key, value in reversed(list(first["paths"].items()))  # type: ignore[union-attr]
        },
        "servers": first["servers"],
        "openapi": first["openapi"],
    }

    first_candidates = _adapter().extract_surfaces(
        _request(),
        _result(json.dumps(first).encode("utf-8")),
    )
    second_candidates = _adapter().extract_surfaces(
        _request(),
        _result(json.dumps(second).encode("utf-8")),
    )

    assert [candidate.locator for candidate in first_candidates] == [
        candidate.locator for candidate in second_candidates
    ]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"target": "https://staging.example.invalid/api/other"}, "target differs"),
        ({"bodySha256": "b" * 64}, "body evidence is inconsistent"),
        ({"unexpected": True}, "validation error"),
    ],
)
def test_http_adapter_rejects_unbound_or_inconsistent_result_data(
    mutation: dict[str, object],
    message: str,
) -> None:
    result = _result(b"{}")
    result.data.update(mutation)

    with pytest.raises(ValueError, match=message):
        _adapter().extract_surfaces(_request(), result)


def test_http_adapter_rejects_malformed_json_claimed_as_json() -> None:
    with pytest.raises(ValueError, match="strict JSON"):
        _adapter().extract_surfaces(
            _request(),
            _result(b'{"openapi":', content_type="application/openapi+json"),
        )


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"openapi": "3.1.0"}, "both version and paths"),
        ({"openapi": "2.0", "paths": {}}, "version is unsupported"),
        (
            {
                "openapi": "3.1.0",
                "servers": [{"url": "https://outside.example.invalid/api"}],
                "paths": {},
            },
            "request origin",
        ),
        (
            {
                "openapi": "3.1.0",
                "servers": [{"url": "https://{tenant}.example.invalid/api"}],
                "paths": {},
            },
            "variables are unsupported",
        ),
        (
            {
                "openapi": "3.1.0",
                "paths": {
                    "/users/{id}/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}
                },
            },
            "parameter names must be unique",
        ),
        (
            {
                "openapi": "3.1.0",
                "paths": {
                    "/users": {
                        "servers": [{"url": "/override"}],
                        "get": {"responses": {"200": {"description": "ok"}}},
                    }
                },
            },
            "path-level server overrides",
        ),
        (
            {
                "openapi": "3.1.0",
                "paths": {
                    "/users": {
                        "get": {
                            "servers": [{"url": "/override"}],
                            "responses": {"200": {"description": "ok"}},
                        }
                    }
                },
            },
            "operation-level server overrides",
        ),
        (
            {
                "openapi": "3.1.0",
                "paths": {"/users": {"get": {"responses": {}}}},
            },
            "operation responses are invalid",
        ),
    ],
)
def test_openapi_adapter_rejects_ambiguous_or_unsupported_schema_features(
    document: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _adapter().extract_surfaces(
            _request(),
            _result(json.dumps(document).encode("utf-8")),
        )


def test_openapi_adapter_rejects_duplicate_json_keys_and_route_overflow() -> None:
    duplicate = b'{"openapi":"3.1.0","paths":{},"paths":{}}'
    with pytest.raises(ValueError, match="not strict JSON"):
        _adapter().extract_surfaces(_request(), _result(duplicate))

    document = {
        "openapi": "3.1.0",
        "paths": {
            "/one": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/two": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
    with pytest.raises(ValueError, match="route limit"):
        _adapter(max_openapi_routes=1).extract_surfaces(
            _request(),
            _result(json.dumps(document).encode("utf-8")),
        )


def test_http_openapi_adapter_registers_exact_surface_kinds_and_context() -> None:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPISurfaceAdapter(
        tool=tool,
        allowed_methods=("POST", "GET"),
        max_openapi_routes=25,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])

    definition = registry.definitions()[0]

    assert definition.supported_surface_kinds == (
        "http-endpoint",
        "http-internal-api",
        "http-route",
    )
    assert definition.requires_trusted_network_receipt is True
    assert definition.tool.tool_id == "http.get"
    assert registry.resolve(definition.reference()).adapter is adapter
    assert adapter.stable_execution_context()["allowedMethods"] == ["GET", "POST"]
    assert (
        adapter.stable_execution_context()["internalAPIOperationExtension"]
        == "x-pajin-internal-api"
    )
    assert adapter.stable_execution_context()["externalRefResolution"] is False


def _campaign_for_http_openapi(sample_campaign: CampaignManifest) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["targets"][0]["endpoint"] = TARGET
    return CampaignManifest.model_validate(payload)


def _sealed_http_source(
    tmp_path: Path,
    campaign: CampaignManifest,
    document: dict[str, object],
    *,
    network_log_trusted: bool = True,
    include_worker_result: bool = True,
    receipt_body: bytes | None = None,
) -> RunStore:
    store = RunStore.create(tmp_path / "source", campaign.metadata.name)
    request = _request()
    body = json.dumps(document).encode("utf-8")
    result = _result(body, request=request)
    decision = PolicyDecision(
        allowed=True,
        reason="all policy checks passed",
        policy="allow",
    )
    store.append_event(
        "campaign.started",
        {"campaign": campaign.metadata.name, "mode": campaign.spec.mode.value},
        occurred_at=NOW - timedelta(seconds=2),
    )
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    store.append_event(
        "tool.policy_evaluated",
        {
            "requestId": request.request_id,
            "toolId": request.tool_id,
            "allowed": True,
            "policy": decision.policy,
            "reason": decision.reason,
        },
        occurred_at=NOW - timedelta(seconds=1),
    )
    evidence: dict[str, object] = {
        "request": request.model_dump(mode="json"),
        "policyDecision": decision.model_dump(mode="json"),
        "result": result.model_dump(mode="json"),
        "networkLogTrusted": network_log_trusted,
    }
    if include_worker_result:
        evidence["workerResult"] = _worker_result(
            request,
            body if receipt_body is None else receipt_body,
        ).model_dump(mode="json")
    store.write_json_create_only(EVIDENCE_REFERENCE, evidence)
    store.append_event(
        "tool.completed",
        {
            "requestId": request.request_id,
            "toolId": request.tool_id,
            "success": True,
            "evidence": EVIDENCE_REFERENCE,
        },
        occurred_at=NOW + timedelta(seconds=1),
    )
    store.seal()
    return store


@pytest.mark.parametrize(
    ("network_log_trusted", "include_worker_result"),
    [(False, True), (True, False)],
)
def test_versioned_http_admission_requires_trusted_network_execution_receipt(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    network_log_trusted: bool,
    include_worker_result: bool,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    source = _sealed_http_source(
        tmp_path,
        campaign,
        _openapi_document(),
        network_log_trusted=network_log_trusted,
        include_worker_result=include_worker_result,
    )

    with pytest.raises(SurfaceAdmissionError, match="trusted network execution receipt"):
        _versioned_producer().produce_from_run(
            source.path,
            evidence_reference=EVIDENCE_REFERENCE,
            expected_run_id=source.run_id,
            admitted_at=NOW + timedelta(minutes=1),
        )


def test_versioned_http_admission_rejects_receipt_result_mismatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    source = _sealed_http_source(
        tmp_path,
        campaign,
        _openapi_document(),
        receipt_body=b'{"openapi":"3.1.0","paths":{}}',
    )

    with pytest.raises(SurfaceAdmissionError, match="does not match"):
        _versioned_producer().produce_from_run(
            source.path,
            evidence_reference=EVIDENCE_REFERENCE,
            expected_run_id=source.run_id,
            admitted_at=NOW + timedelta(minutes=1),
        )


def _versioned_producer(
    *,
    allowed_methods: tuple[str, ...] = ("GET", "POST"),
) -> TrustedSurfaceProducer:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPISurfaceAdapter(
        tool=tool,
        allowed_methods=allowed_methods,
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    return TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[definition.reference() for definition in registry.definitions()],
    )


def test_versioned_http_openapi_admission_binds_routes_scope_and_projection_audit(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    source = _sealed_http_source(tmp_path, campaign, _openapi_document())

    admission = _versioned_producer().produce_from_run(
        source.path,
        evidence_reference=EVIDENCE_REFERENCE,
        expected_run_id=source.run_id,
        admitted_at=NOW + timedelta(minutes=1),
    )

    assert admission.adapter_reference is not None
    assert len(admission.surface_set.surfaces) == 3
    assert {surface.locator.kind for surface in admission.surface_set.surfaces} == {
        "http-endpoint",
        "http-route",
    }
    projection = RunStore.create(tmp_path / "projection", campaign.metadata.name)
    publish_surface_projection(projection, admission)
    event = next(
        item
        for item in load_verified_run_events(projection.path)
        if item.event_type == "discovery.attack-surface-set.published"
    )
    assert event.payload["adapterId"] == "pajin.discovery.http-openapi:http.get"
    assert event.payload["adapterDigest"] == admission.adapter_reference.adapter_digest


def test_versioned_openapi_authentication_admission_reuses_route_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    document = _openapi_document()
    document["components"] = {
        "securitySchemes": {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    }
    document["security"] = [{"BearerAuth": []}]
    source = _sealed_http_source(tmp_path, campaign, document)
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIAuthenticationSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[definition.reference() for definition in registry.definitions()],
    )

    admission = producer.produce_from_run(
        source.path,
        evidence_reference=EVIDENCE_REFERENCE,
        expected_run_id=source.run_id,
        admitted_at=NOW + timedelta(minutes=1),
    )

    authentication_surfaces = [
        surface
        for surface in admission.surface_set.surfaces
        if isinstance(surface.locator, HTTPAuthenticationSurfaceLocator)
    ]
    assert {
        (surface.locator.route.method, surface.locator.route.path_template)
        for surface in authentication_surfaces
    } == {
        ("GET", "/users/{user_id}"),
        ("POST", "/users/{user_id}"),
    }
    projection = RunStore.create(tmp_path / "auth-projection", campaign.metadata.name)
    publish_surface_projection(projection, admission)
    event = next(
        item
        for item in load_verified_run_events(projection.path)
        if item.event_type == "discovery.attack-surface-set.published"
    )
    assert (
        event.payload["adapterId"]
        == "pajin.discovery.http-openapi-authentication:http.get"
    )
    assert event.payload["adapterDigest"] == admission.adapter_reference.adapter_digest


def test_versioned_openapi_file_upload_admission_reuses_route_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    document = _openapi_document()
    paths = document["paths"]
    assert isinstance(paths, dict)
    users = paths["/users/{user_id}"]
    assert isinstance(users, dict)
    post = users["post"]
    assert isinstance(post, dict)
    post["requestBody"] = {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["document"],
                    "properties": {
                        "document": {
                            "type": "string",
                            "format": "binary",
                        }
                    },
                }
            }
        },
    }
    source = _sealed_http_source(tmp_path, campaign, document)
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIFileUploadSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[definition.reference() for definition in registry.definitions()],
    )

    admission = producer.produce_from_run(
        source.path,
        evidence_reference=EVIDENCE_REFERENCE,
        expected_run_id=source.run_id,
        admitted_at=NOW + timedelta(minutes=1),
    )

    upload = next(
        surface.locator
        for surface in admission.surface_set.surfaces
        if isinstance(surface.locator, HTTPFileUploadSurfaceLocator)
    )
    assert upload.route.path_template == "/users/{user_id}"
    assert upload.route.method == "POST"
    assert upload.request_body_required is True
    assert upload.uploads[0].field_name == "document"
    projection = RunStore.create(tmp_path / "upload-projection", campaign.metadata.name)
    publish_surface_projection(projection, admission)
    event = next(
        item
        for item in load_verified_run_events(projection.path)
        if item.event_type == "discovery.attack-surface-set.published"
    )
    assert (
        event.payload["adapterId"]
        == "pajin.discovery.http-openapi-file-upload:http.get"
    )
    assert event.payload["adapterDigest"] == admission.adapter_reference.adapter_digest


def test_versioned_openapi_rag_admission_reuses_route_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    document = _openapi_document()
    paths = document["paths"]
    assert isinstance(paths, dict)
    users = paths["/users/{user_id}"]
    assert isinstance(users, dict)
    post = users["post"]
    assert isinstance(post, dict)
    post["x-pajin-rag"] = {
        "version": "1",
        "boundary": "retrieval",
        "corpusIds": ["customer-documents"],
        "indexIds": ["semantic-primary"],
    }
    source = _sealed_http_source(tmp_path, campaign, document)
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIRAGSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[
            definition.reference() for definition in registry.definitions()
        ],
    )

    admission = producer.produce_from_run(
        source.path,
        evidence_reference=EVIDENCE_REFERENCE,
        expected_run_id=source.run_id,
        admitted_at=NOW + timedelta(minutes=1),
    )

    rag = next(
        surface.locator
        for surface in admission.surface_set.surfaces
        if isinstance(surface.locator, HTTPRAGSurfaceLocator)
    )
    assert rag.route.path_template == "/users/{user_id}"
    assert rag.route.method == "POST"
    assert rag.boundary == "retrieval"
    assert rag.corpus_ids == ("customer-documents",)
    assert rag.index_ids == ("semantic-primary",)
    projection = RunStore.create(tmp_path / "rag-projection", campaign.metadata.name)
    publish_surface_projection(projection, admission)
    event = next(
        item
        for item in load_verified_run_events(projection.path)
        if item.event_type == "discovery.attack-surface-set.published"
    )
    assert event.payload["adapterId"] == "pajin.discovery.http-openapi-rag:http.get"
    assert event.payload["adapterDigest"] == admission.adapter_reference.adapter_digest


def test_http_route_admission_rejects_method_or_scope_expansion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    out_of_scope = {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {"/admin/delete": {"post": {"responses": {"200": {"description": "unexpected"}}}}},
    }
    source = _sealed_http_source(tmp_path, campaign, out_of_scope)
    with pytest.raises(SurfaceAdmissionError, match="explicit deny rule"):
        _versioned_producer().produce_from_run(
            source.path,
            evidence_reference=EVIDENCE_REFERENCE,
            expected_run_id=source.run_id,
            admitted_at=NOW + timedelta(minutes=1),
        )

    delete_route = {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {"/users": {"delete": {"responses": {"204": {"description": "deleted"}}}}},
    }
    second = _sealed_http_source(tmp_path / "method", campaign, delete_route)
    with pytest.raises(SurfaceAdmissionError, match="method exceeds Campaign authority"):
        _versioned_producer(allowed_methods=("GET", "DELETE")).produce_from_run(
            second.path,
            evidence_reference=EVIDENCE_REFERENCE,
            expected_run_id=second.run_id,
            admitted_at=NOW + timedelta(minutes=1),
        )


class _MisdeclaredHTTPAdapter(HTTPAndOpenAPISurfaceAdapter):
    supported_surface_kinds = ("http-endpoint",)

    def stable_execution_context(self) -> dict[str, object]:
        return dict(super().stable_execution_context())


def test_versioned_admission_rejects_adapter_output_kind_not_in_definition(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign_for_http_openapi(sample_campaign)
    source = _sealed_http_source(tmp_path, campaign, _openapi_document())
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = _MisdeclaredHTTPAdapter(tool=tool, allowed_methods=("GET", "POST"))
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[definition.reference() for definition in registry.definitions()],
    )

    with pytest.raises(SurfaceAdmissionError, match="undeclared Surface kind"):
        producer.produce_from_run(
            source.path,
            evidence_reference=EVIDENCE_REFERENCE,
            expected_run_id=source.run_id,
            admitted_at=NOW + timedelta(minutes=1),
        )


@pytest.mark.parametrize(
    ("allow", "deny", "message"),
    [
        (
            [
                TARGET,
                "https://staging.example.invalid/api/users/pajin-route-parameter",
            ],
            [],
            "not fully covered",
        ),
        (
            ["https://staging.example.invalid/api/**"],
            ["https://staging.example.invalid/api/users/admin"],
            "may overlap an explicit Campaign deny",
        ),
    ],
)
def test_parameterized_route_requires_full_allow_and_no_possible_narrow_deny(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    allow: list[str],
    deny: list[str],
    message: str,
) -> None:
    campaign_payload = _campaign_for_http_openapi(sample_campaign).model_dump(
        mode="json",
        by_alias=True,
    )
    campaign_payload["spec"]["scope"] = {"allow": allow, "deny": deny}
    campaign = CampaignManifest.model_validate(campaign_payload)
    document = {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {"/users/{user_id}": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    source = _sealed_http_source(tmp_path, campaign, document)

    with pytest.raises(SurfaceAdmissionError, match=message):
        _versioned_producer().produce_from_run(
            source.path,
            evidence_reference=EVIDENCE_REFERENCE,
            expected_run_id=source.run_id,
            admitted_at=NOW + timedelta(minutes=1),
        )
