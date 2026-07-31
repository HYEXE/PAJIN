from __future__ import annotations

import asyncio
import json
from base64 import b64encode
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.discovery import (
    DeterministicRAGInjectionHypothesisCompiler,
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIFileUploadSurfaceAdapter,
    HTTPAndOpenAPIRAGSurfaceAdapter,
    HTTPRAGInjectionReconPlanner,
    RAGInjectionHypothesisAuthority,
    RAGInjectionHypothesisError,
    RAGInjectionHypothesisRunner,
    ReconWaveError,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import (
    RunIntegrityError,
    load_verified_run_events,
    verify_run_integrity,
)
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


def _operation(*, upload: bool, boundary: str | None) -> dict[str, object]:
    operation: dict[str, object] = {
        "responses": {"202": {"description": "accepted"}},
    }
    if upload:
        operation["requestBody"] = {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["document"],
                        "properties": {"document": {"type": "string", "format": "binary"}},
                    }
                }
            },
        }
    if boundary is not None:
        operation["x-pajin-rag"] = {
            "version": "1",
            "boundary": boundary,
            "corpusIds": ["knowledge-base"] if boundary == "corpus-ingest" else [],
            "indexIds": [] if boundary == "corpus-ingest" else ["primary-index"],
        }
    return operation


def _openapi_document(
    *,
    include_upload: bool = True,
    rag_boundary: str | None = "corpus-ingest",
    co_located: bool = True,
) -> dict[str, object]:
    paths: dict[str, object] = {
        "/documents": {
            "post": _operation(
                upload=include_upload,
                boundary=rag_boundary if co_located else None,
            )
        }
    }
    if not co_located and rag_boundary is not None:
        paths["/corpora"] = {
            "post": _operation(upload=False, boundary=rag_boundary),
        }
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": paths,
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
        assert json.loads(job.stdin) == {"target": TARGET}
        occurred_at = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(
                {
                    "target": TARGET,
                    "status": 200,
                    "contentType": "application/json",
                    "bodyPreview": body.decode("utf-8"),
                    "bodySha256": body_digest,
                    "responseBodyBase64": b64encode(body).decode("ascii"),
                },
                separators=(",", ":"),
            ),
            network_log="\n".join(
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
            ),
            started_at=occurred_at,
            finished_at=occurred_at,
        )

    monkeypatch.setattr(DockerWorkerBackend, "run", run)
    return DockerWorkerBackend(allowed_images={"pajin-worker:dev"})


def _recon_runner(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> tuple[SingleReconWaveRunner, HTTPRAGInjectionReconPlanner]:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIRAGSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[reference],
    )
    planner = HTTPRAGInjectionReconPlanner(
        tool=tool,
        target_id=campaign.spec.targets[0].id,
        adapter_reference=reference,
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


def _recon(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
):
    runner, _ = _recon_runner(tmp_path, campaign, monkeypatch, document)
    return asyncio.run(runner.run(campaign))


def test_rag_injection_recon_plan_binds_disc_003c_and_both_surface_kinds(
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign(sample_campaign)
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    rag_adapter = HTTPAndOpenAPIRAGSurfaceAdapter(tool=tool)
    rag_registry = DiscoveryAdapterRegistry(tools=tools, adapters=[rag_adapter])
    planner = HTTPRAGInjectionReconPlanner(
        tool=tool,
        target_id=campaign.spec.targets[0].id,
        adapter_reference=rag_registry.definitions()[0].reference(),
    )

    assert planner.plan(campaign) == planner.plan(campaign.model_copy(deep=True))
    plan = planner.plan(campaign)
    assert plan.adapter_reference == rag_registry.definitions()[0].reference()
    assert plan.required_surface_kinds == ("http-file-upload", "http-rag")
    assert plan.request.target == TARGET
    assert plan.request.method == "GET"

    file_adapter = HTTPAndOpenAPIFileUploadSurfaceAdapter(tool=tool)
    file_registry = DiscoveryAdapterRegistry(tools=tools, adapters=[file_adapter])
    with pytest.raises(ValueError, match="DISC-003C"):
        HTTPRAGInjectionReconPlanner(
            tool=tool,
            target_id=campaign.spec.targets[0].id,
            adapter_reference=file_registry.definitions()[0].reference(),
        )


def test_walking_rag_injection_seals_deterministic_non_executable_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    compiler = DeterministicRAGInjectionHypothesisCompiler()

    first = compiler.compile(campaign, recon)
    second = compiler.compile(campaign.model_copy(deep=True), recon)
    assert first == second
    assert len(first) == 1
    hypothesis = first[0]
    assert hypothesis.execution_state == "not-authorized"
    assert hypothesis.rag_locator.boundary == "corpus-ingest"
    assert hypothesis.rag_locator.route == hypothesis.upload_locator.route
    assert hypothesis.dependency_surface_ids == (hypothesis.upload_surface_id,)
    assert hypothesis.required_tool_id == "rag-document-probe"
    assert hypothesis.max_tool_calls == 4
    assert hypothesis.surface_snapshot.surface_set_id == recon.surface_set.surface_set_id

    outcome = RAGInjectionHypothesisRunner(
        compiler=compiler,
        output_root=tmp_path,
    ).run(campaign, recon)
    assert verify_run_integrity(outcome.run_path).valid
    artifact = json.loads((outcome.run_path / outcome.artifact_path).read_text("utf-8"))
    assert artifact == [hypothesis.model_dump(mode="json", by_alias=True)]
    assert "request" not in artifact[0]
    assert "capability" not in artifact[0]
    events = load_verified_run_events(outcome.run_path)
    assert (
        sum(event.event_type == "walking.rag-injection-hypotheses.created" for event in events) == 1
    )
    assert not any(
        event.event_type in {"capability.issued", "worker.dispatched"} for event in events
    )


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (_openapi_document(co_located=False), "co-located upload Surface"),
        (
            _openapi_document(rag_boundary="retrieval"),
            "no explicit corpus-ingest",
        ),
    ],
)
def test_rag_injection_compiler_rejects_scope_expansion_and_wrong_boundary(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
    message: str,
) -> None:
    campaign = _campaign(sample_campaign)
    recon = _recon(tmp_path, campaign, monkeypatch, document)

    with pytest.raises(RAGInjectionHypothesisError, match=message):
        DeterministicRAGInjectionHypothesisCompiler().compile(campaign, recon)


def test_rag_injection_recon_does_not_infer_rag_from_upload_names(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    runner, _ = _recon_runner(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(rag_boundary=None),
    )

    with pytest.raises(ReconWaveError, match="required Surface kind"):
        asyncio.run(runner.run(campaign))

    run_paths = list((tmp_path / campaign.metadata.name).glob("run_*"))
    assert len(run_paths) == 1
    assert verify_run_integrity(run_paths[0]).valid
    assert not any(
        event.event_type == "discovery.attack-surface-set.published"
        for event in load_verified_run_events(run_paths[0])
    )


def test_rag_injection_compiler_rejects_campaign_and_plan_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    compiler = DeterministicRAGInjectionHypothesisCompiler()
    changed_payload = campaign.model_dump(mode="json", by_alias=True)
    changed_payload["spec"]["targets"][0]["endpoint"] = (
        "https://other.example.invalid/api/openapi.json"
    )
    changed_campaign = CampaignManifest.model_validate(changed_payload)

    with pytest.raises(RAGInjectionHypothesisError, match="Campaign differs"):
        compiler.compile(changed_campaign, recon)

    forged_plan = recon.plan.model_copy(update={"planner_id": "forged.walk.v1"}, deep=True)
    with pytest.raises(RAGInjectionHypothesisError, match="Plan differs"):
        compiler.compile(campaign, replace(recon, plan=forged_plan))


def test_rag_injection_authority_rejects_digest_forgery_and_seal_mutation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    compiler = DeterministicRAGInjectionHypothesisCompiler()
    hypothesis = compiler.compile(campaign, recon)[0]
    payload = hypothesis.model_dump(mode="json", by_alias=True)
    payload["hypothesisDigest"] = "0" * 64
    with pytest.raises(ValueError, match="Digest differs"):
        RAGInjectionHypothesisAuthority.model_validate(payload)

    outcome = RAGInjectionHypothesisRunner(
        compiler=compiler,
        output_root=tmp_path,
    ).run(campaign, recon)
    (outcome.run_path / outcome.artifact_path).write_text("[]", encoding="utf-8")
    with pytest.raises(RunIntegrityError):
        verify_run_integrity(outcome.run_path)
