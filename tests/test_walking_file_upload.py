from __future__ import annotations

import asyncio
import json
from base64 import b64encode
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIFileUploadSurfaceAdapter,
    HTTPAndOpenAPISurfaceAdapter,
    HTTPFileUploadReconPlanner,
    HTTPFileUploadSurfaceLocator,
    ReconWaveError,
    ReconWavePlan,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import load_verified_run_events, verify_run_integrity
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import (
    EGRESS_HTTP_RECEIPT_VERSION,
    ToolRegistry,
    audit_http_target,
    http_target_sha256,
)
from pajin.tools.http import HTTPGetTool

TARGET = "https://staging.example.invalid/api/openapi.json"


def _campaign(sample_campaign: CampaignManifest) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["targets"][0]["endpoint"] = TARGET
    return CampaignManifest.model_validate(payload)


def _openapi_document(*, include_upload: bool = True) -> dict[str, object]:
    request_body: dict[str, object]
    if include_upload:
        request_body = {
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
                            },
                            "description": {"type": "string"},
                        },
                    }
                }
            },
        }
    else:
        request_body = {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"description": {"type": "string"}},
                    }
                }
            }
        }
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/documents": {
                "post": {
                    "requestBody": request_body,
                    "responses": {"202": {"description": "accepted"}},
                }
            }
        },
    }


def _docker_backend(
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> DockerWorkerBackend:
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    body_digest = sha256(body).hexdigest()

    async def run(
        self: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[object] | None = None,
    ) -> WorkerResult:
        del self
        assert not secrets
        assert job.network is NetworkMode.EGRESS_PROXY
        request = json.loads(job.stdin)
        assert request == {"target": TARGET}
        occurred_at = datetime.now(UTC)
        stdout = json.dumps(
            {
                "target": TARGET,
                "status": 200,
                "contentType": "application/json",
                "bodyPreview": body.decode("utf-8"),
                "bodySha256": body_digest,
                "responseBodyBase64": b64encode(body).decode("ascii"),
            },
            separators=(",", ":"),
        )
        network_log = "\n".join(
            [
                json.dumps({"event": "ready", "port": 8080}),
                json.dumps(
                    {
                        "event": "allow",
                        "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
                        "sequence": 1,
                        "method": "GET",
                        "target": audit_http_target(TARGET),
                        "targetSha256": http_target_sha256(TARGET),
                        "address": "203.0.113.10",
                        "status": 200,
                        "responseBodySha256": body_digest,
                    }
                ),
            ]
        )
        return WorkerResult(
            execution_id=job.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=stdout,
            network_log=network_log,
            started_at=occurred_at,
            finished_at=occurred_at,
        )

    monkeypatch.setattr(DockerWorkerBackend, "run", run)
    return DockerWorkerBackend(allowed_images={"pajin-worker:dev"})


def _runner(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
    *,
    planned_max_file_uploads: int = 64,
    admitted_max_file_uploads: int | None = None,
) -> tuple[SingleReconWaveRunner, HTTPFileUploadReconPlanner]:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    planned_adapter = HTTPAndOpenAPIFileUploadSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
        max_file_uploads=planned_max_file_uploads,
    )
    planned_registry = DiscoveryAdapterRegistry(
        tools=tools,
        adapters=[planned_adapter],
    )
    planned_reference = planned_registry.definitions()[0].reference()
    admitted_adapter = (
        planned_adapter
        if admitted_max_file_uploads is None
        else HTTPAndOpenAPIFileUploadSurfaceAdapter(
            tool=tool,
            allowed_methods=("GET", "POST"),
            max_file_uploads=admitted_max_file_uploads,
        )
    )
    admitted_registry = DiscoveryAdapterRegistry(
        tools=tools,
        adapters=[admitted_adapter],
    )
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=admitted_registry,
        adapter_references=[
            definition.reference() for definition in admitted_registry.definitions()
        ],
    )
    planner = HTTPFileUploadReconPlanner(
        tool=tool,
        target_id=campaign.spec.targets[0].id,
        adapter_reference=planned_reference,
    )
    return (
        SingleReconWaveRunner(
            planner=planner,
            producer=producer,
            tools=tools,
            policy=PolicyEngine(),
            worker=_docker_backend(monkeypatch, document),
            output_root=tmp_path,
        ),
        planner,
    )


def test_file_upload_recon_plan_is_campaign_and_adapter_bound(
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign(sample_campaign)
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIFileUploadSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    planner = HTTPFileUploadReconPlanner(
        tool=tool,
        target_id=campaign.spec.targets[0].id,
        adapter_reference=reference,
    )

    first = planner.plan(campaign)
    second = planner.plan(campaign.model_copy(deep=True))

    assert first == second
    assert first.request.tool_id == HTTPGetTool.spec.tool_id
    assert first.request.target == TARGET
    assert first.request.method == "GET"
    assert first.request.arguments == {}
    assert first.adapter_reference == reference
    assert first.required_surface_kinds == ("http-file-upload",)

    old_payload = first.model_dump(mode="json", by_alias=True)
    old_payload.pop("adapterReference")
    old_payload.pop("requiredSurfaceKinds")
    legacy = ReconWavePlan.model_validate(old_payload)
    assert legacy.adapter_reference is None
    assert legacy.required_surface_kinds == ()

    generic = HTTPAndOpenAPISurfaceAdapter(tool=tool)
    generic_registry = DiscoveryAdapterRegistry(tools=tools, adapters=[generic])
    with pytest.raises(ValueError, match="DISC-003B"):
        HTTPFileUploadReconPlanner(
            tool=tool,
            target_id=campaign.spec.targets[0].id,
            adapter_reference=generic_registry.definitions()[0].reference(),
        )


def test_walking_file_upload_recon_publishes_exact_admitted_surface(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    runner, planner = _runner(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(),
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.plan == planner.plan(campaign)
    assert verify_run_integrity(outcome.source_run_path).valid
    assert verify_run_integrity(outcome.projection_run_path).valid
    uploads = [
        surface
        for surface in outcome.surface_set.surfaces
        if isinstance(surface.locator, HTTPFileUploadSurfaceLocator)
    ]
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload.locator.route.path_template == "/documents"
    assert upload.locator.route.method == "POST"
    assert upload.locator.request_body_required is True
    assert upload.locator.uploads[0].field_name == "document"
    assert upload.locator.uploads[0].encoding == "binary"
    assert upload.observation_ids

    source_events = load_verified_run_events(outcome.source_run_path)
    planned = next(
        event for event in source_events if event.event_type == "discovery.recon-plan.created"
    )
    assert planned.payload["adapterReference"] == outcome.plan.adapter_reference.model_dump(
        mode="json",
        by_alias=True,
    )
    assert planned.payload["requiredSurfaceKinds"] == ["http-file-upload"]
    projection_events = load_verified_run_events(outcome.projection_run_path)
    published = next(
        event
        for event in projection_events
        if event.event_type == "discovery.attack-surface-set.published"
    )
    assert published.payload["adapterId"] == ("pajin.discovery.http-openapi-file-upload:http.get")
    assert published.payload["adapterDigest"] == (outcome.plan.adapter_reference.adapter_digest)


@pytest.mark.parametrize(
    ("document", "admitted_max_file_uploads", "message"),
    [
        (_openapi_document(include_upload=False), None, "required Surface kind"),
        (_openapi_document(), 12, "adapter differs"),
    ],
)
def test_walking_file_upload_recon_fails_before_projection_on_authority_gap(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
    admitted_max_file_uploads: int | None,
    message: str,
) -> None:
    campaign = _campaign(sample_campaign)
    runner, _ = _runner(
        tmp_path,
        campaign,
        monkeypatch,
        document,
        admitted_max_file_uploads=admitted_max_file_uploads,
    )

    with pytest.raises(ReconWaveError, match=message):
        asyncio.run(runner.run(campaign))

    run_paths = list((tmp_path / campaign.metadata.name).glob("run_*"))
    assert len(run_paths) == 1
    assert verify_run_integrity(run_paths[0]).valid
    assert not any(
        event.event_type == "discovery.attack-surface-set.published"
        for event in load_verified_run_events(run_paths[0])
    )


def test_file_upload_recon_rejects_undeclared_target_before_dispatch(
    sample_campaign: CampaignManifest,
) -> None:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIFileUploadSurfaceAdapter(tool=tool)
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    planner = HTTPFileUploadReconPlanner(
        tool=tool,
        target_id="missing-target",
        adapter_reference=registry.definitions()[0].reference(),
    )

    with pytest.raises(ReconWaveError, match="not declared exactly once"):
        planner.plan(sample_campaign)
