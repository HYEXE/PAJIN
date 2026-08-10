from __future__ import annotations

import asyncio
import json
from base64 import b64encode
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPITenantDataSurfaceAdapter,
    HTTPDataResponseSurfaceLocator,
    HTTPRAGSurfaceLocator,
    HTTPRouteSurfaceLocator,
    HTTPTenantDataRetrievalReconPlanner,
    HTTPTenantRetrievalSurfaceLocator,
    ModeNeutralTenantAttackChainAuthority,
    ModeNeutralTenantAttackChainError,
    ReconWaveError,
    ReconWaveOutcome,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
    compile_cross_tenant_data_exposure_chain,
    registered_cross_tenant_data_exposure_chain_contract,
    verify_cross_tenant_data_exposure_chain,
)
from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretMaterial
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

TARGET = "https://staging.example.invalid/api/tenant/openapi.json"


def _campaign(sample_campaign: CampaignManifest, mode: CampaignMode) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["mode"] = mode.value
    payload["spec"]["targets"][0]["id"] = "tenant-search-api"
    payload["spec"]["targets"][0]["endpoint"] = TARGET
    payload["spec"]["targets"][0]["simulation"] = {}
    return CampaignManifest.model_validate(payload)


def _openapi_document(
    *,
    include_tenant: bool = True,
    include_data: bool = True,
) -> dict[str, object]:
    operation: dict[str, object] = {
        "x-pajin-rag": {
            "version": "1",
            "boundary": "retrieval",
            "indexIds": ["customer-search"],
        },
        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
        "responses": {
            "200": {
                "description": "results",
                "content": {"application/json": {"schema": {"type": "object"}}},
            }
        },
    }
    if include_tenant:
        operation["x-pajin-tenant-retrieval"] = {
            "version": "1",
            "tenantSelector": {"location": "header", "name": "X-Tenant-ID"},
        }
    if include_data:
        operation["x-pajin-data-response"] = {
            "version": "1",
            "dataClasses": ["customer-content", "support-record"],
        }
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {"/tenant-search": {"post": operation}},
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
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del self
        assert not secrets
        assert job.network is NetworkMode.EGRESS_PROXY
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


def _recon(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> ReconWaveOutcome:
    tool = HTTPGetTool()
    tools = ToolRegistry()
    tools.register(tool)
    adapter = HTTPAndOpenAPITenantDataSurfaceAdapter(
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
    runner = SingleReconWaveRunner(
        planner=HTTPTenantDataRetrievalReconPlanner(
            tool=tool,
            target_id="tenant-search-api",
            adapter_reference=reference,
        ),
        producer=producer,
        tools=tools,
        policy=PolicyEngine(),
        worker=_docker_backend(monkeypatch, document),
        output_root=tmp_path,
    )
    return asyncio.run(runner.run(campaign))


def _surface_ids(recon: ReconWaveOutcome) -> tuple[str, str]:
    tenant = [
        surface
        for surface in recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPTenantRetrievalSurfaceLocator)
    ]
    data = [
        surface
        for surface in recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPDataResponseSurfaceLocator)
    ]
    assert len(tenant) == len(data) == 1
    return tenant[0].surface_id, data[0].surface_id


def test_chain004_contract_is_deterministic_mode_neutral_and_non_executable() -> None:
    first = registered_cross_tenant_data_exposure_chain_contract()
    second = registered_cross_tenant_data_exposure_chain_contract()

    assert first == second
    assert first.chain_id == "chain-004:cross-tenant-retrieval-data-exposure"
    assert [stage.stage_id for stage in first.stages] == [
        "cross-tenant-retrieval",
        "data-exposure",
    ]
    assert first.campaign_mode_constraint == "none"
    assert first.chain_state == "hypothesized-not-validated"
    assert first.tenant_values_retained is False
    assert first.cross_tenant_access_confirmed is False
    assert first.data_exposure_confirmed is False
    assert first.execution_authorized is False
    assert first.finding_confirmed is False


@pytest.mark.parametrize("mode", list(CampaignMode))
def test_chain004_compiles_the_same_closed_contract_for_every_campaign_mode(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    mode: CampaignMode,
) -> None:
    campaign = _campaign(sample_campaign, mode)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    tenant_id, data_id = _surface_ids(recon)

    authority = compile_cross_tenant_data_exposure_chain(
        campaign,
        recon,
        tenant_retrieval_surface_id=tenant_id,
        data_response_surface_id=data_id,
    )

    assert authority.contract == registered_cross_tenant_data_exposure_chain_contract()
    assert [stage.execution_state for stage in authority.stages] == [
        "discovered-not-authorized",
        "discovered-not-authorized",
    ]
    assert authority.stages[0].surface.target_id == authority.stages[1].surface.target_id
    assert authority.surface_evidence_only is True
    assert authority.cross_tenant_access_confirmed is False
    assert authority.data_exposure_confirmed is False
    assert authority.execution_authorized is False
    assert verify_cross_tenant_data_exposure_chain(authority, campaign, recon) == authority


def test_chain004_rejects_generic_rag_and_route_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    retrievals = [
        surface
        for surface in recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPRAGSurfaceLocator)
        and surface.locator.boundary == "retrieval"
    ]
    routes = [
        surface
        for surface in recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPRouteSurfaceLocator)
        and surface.locator.path_template == "/tenant-search"
    ]
    assert len(retrievals) == len(routes) == 1

    with pytest.raises(ModeNeutralTenantAttackChainError):
        compile_cross_tenant_data_exposure_chain(
            campaign,
            recon,
            tenant_retrieval_surface_id=retrievals[0].surface_id,
            data_response_surface_id=routes[0].surface_id,
        )


def test_chain004_rejects_cross_route_surface_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    document = _openapi_document()
    paths = document["paths"]
    assert isinstance(paths, dict)
    paths["/other-tenant-search"] = json.loads(json.dumps(paths["/tenant-search"]))
    recon = _recon(tmp_path, campaign, monkeypatch, document)
    tenants = [
        surface
        for surface in recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPTenantRetrievalSurfaceLocator)
    ]
    data_responses = [
        surface
        for surface in recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPDataResponseSurfaceLocator)
    ]
    tenant = next(
        surface
        for surface in tenants
        if surface.locator.retrieval.route.path_template == "/tenant-search"
    )
    data = next(
        surface
        for surface in data_responses
        if surface.locator.route.path_template == "/other-tenant-search"
    )

    with pytest.raises(ModeNeutralTenantAttackChainError):
        compile_cross_tenant_data_exposure_chain(
            campaign,
            recon,
            tenant_retrieval_surface_id=tenant.surface_id,
            data_response_surface_id=data.surface_id,
        )


@pytest.mark.parametrize(
    ("include_tenant", "include_data"),
    [(False, True), (True, False)],
)
def test_tenant_data_recon_fails_closed_when_a_declaration_is_missing(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    include_tenant: bool,
    include_data: bool,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)

    with pytest.raises(ReconWaveError, match="lacks a required Surface kind"):
        _recon(
            tmp_path,
            campaign,
            monkeypatch,
            _openapi_document(
                include_tenant=include_tenant,
                include_data=include_data,
            ),
        )


def test_chain004_rejects_authority_forgery_and_stale_publication(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    tenant_id, data_id = _surface_ids(recon)
    authority = compile_cross_tenant_data_exposure_chain(
        campaign,
        recon,
        tenant_retrieval_surface_id=tenant_id,
        data_response_surface_id=data_id,
    )
    payload = authority.model_dump(mode="json", by_alias=True)
    payload["dataExposureConfirmed"] = True
    with pytest.raises(ValidationError):
        ModeNeutralTenantAttackChainAuthority.model_validate(payload)

    substituted = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    with pytest.raises(ModeNeutralTenantAttackChainError):
        verify_cross_tenant_data_exposure_chain(authority, campaign, substituted)


def test_chain004_rejects_tampered_projection(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    tenant_id, data_id = _surface_ids(recon)
    authority = compile_cross_tenant_data_exposure_chain(
        campaign,
        recon,
        tenant_retrieval_surface_id=tenant_id,
        data_response_surface_id=data_id,
    )
    artifact = recon.projection_run_path / recon.publication.artifact_path
    artifact.write_bytes(artifact.read_bytes() + b"\n")

    with pytest.raises(ModeNeutralTenantAttackChainError):
        verify_cross_tenant_data_exposure_chain(authority, campaign, recon)
