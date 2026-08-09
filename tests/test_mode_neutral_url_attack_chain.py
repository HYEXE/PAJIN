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
    HTTPAndOpenAPISurfaceAdapter,
    HTTPInternalAPIReconPlanner,
    HTTPInternalAPISurfaceLocator,
    HTTPRouteSurfaceLocator,
    MCPBoundarySurfaceAdapter,
    MCPPromptSurfaceLocator,
    MCPToolSurfaceLocator,
    MCPURLToolSurfaceLocator,
    ModeNeutralURLAttackChainAuthority,
    ModeNeutralURLAttackChainError,
    ReconWaveError,
    ReconWaveOutcome,
    RegisteredMCPBoundaryReconPlanner,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
    compile_prompt_url_internal_api_chain,
    registered_prompt_url_internal_api_chain_contract,
    verify_prompt_url_internal_api_chain,
)
from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    SimulatedWorkerBackend,
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
from pajin.tools.mcp import demo_mcp_discovery_tool

MCP_TARGET = "https://staging.example.invalid/api/mcp/demo-security"
OPENAPI_TARGET = "https://staging.example.invalid/api/internal/openapi.json"


def _campaign(sample_campaign: CampaignManifest, mode: CampaignMode) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["mode"] = mode.value
    template = payload["spec"]["targets"][0]
    payload["spec"]["targets"] = [
        {
            **template,
            "id": "mcp-assistant",
            "endpoint": MCP_TARGET,
        },
        {
            **template,
            "id": "internal-api-spec",
            "endpoint": OPENAPI_TARGET,
            "simulation": {},
        },
    ]
    return CampaignManifest.model_validate(payload)


def _openapi_document(*, internal: object = True) -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/internal/status": {
                "get": {
                    "x-pajin-internal-api": internal,
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }


def _mcp_recon(tmp_path: Path, campaign: CampaignManifest) -> ReconWaveOutcome:
    tool = demo_mcp_discovery_tool()
    tools = ToolRegistry()
    tools.register(tool)
    adapter = MCPBoundarySurfaceAdapter(tool=tool)
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[registry.definitions()[0].reference()],
    )
    runner = SingleReconWaveRunner(
        planner=RegisteredMCPBoundaryReconPlanner(
            tool=tool,
            target_id="mcp-assistant",
        ),
        producer=producer,
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=tmp_path,
    )
    return asyncio.run(runner.run(campaign))


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
                    "target": OPENAPI_TARGET,
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
                            "target": audit_http_target(OPENAPI_TARGET),
                            "targetSha256": http_target_sha256(OPENAPI_TARGET),
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


def _http_recon(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> ReconWaveOutcome:
    tool = HTTPGetTool()
    tools = ToolRegistry()
    tools.register(tool)
    adapter = HTTPAndOpenAPISurfaceAdapter(tool=tool)
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[reference],
    )
    runner = SingleReconWaveRunner(
        planner=HTTPInternalAPIReconPlanner(
            tool=tool,
            target_id="internal-api-spec",
            adapter_reference=reference,
        ),
        producer=producer,
        tools=tools,
        policy=PolicyEngine(),
        worker=_docker_backend(monkeypatch, document),
        output_root=tmp_path,
    )
    return asyncio.run(runner.run(campaign))


def _surface_ids(
    mcp_recon: ReconWaveOutcome,
    internal_recon: ReconWaveOutcome,
) -> tuple[str, str, str]:
    prompts = [
        surface
        for surface in mcp_recon.surface_set.surfaces
        if isinstance(surface.locator, MCPPromptSurfaceLocator)
        and surface.locator.prompt_name == "inspect_prompt"
    ]
    url_tools = [
        surface
        for surface in mcp_recon.surface_set.surfaces
        if isinstance(surface.locator, MCPURLToolSurfaceLocator)
        and surface.locator.tool_name == "inspect_url"
    ]
    internal_apis = [
        surface
        for surface in internal_recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPInternalAPISurfaceLocator)
        and surface.locator.route.path_template == "/internal/status"
    ]
    assert len(prompts) == len(url_tools) == len(internal_apis) == 1
    return (
        prompts[0].surface_id,
        url_tools[0].surface_id,
        internal_apis[0].surface_id,
    )


def test_chain003_contract_is_deterministic_mode_neutral_and_non_executable() -> None:
    first = registered_prompt_url_internal_api_chain_contract()
    second = registered_prompt_url_internal_api_chain_contract()

    assert first == second
    assert first.chain_id == "chain-003:prompt-injection-url-tool-internal-api"
    assert [stage.stage_id for stage in first.stages] == [
        "prompt-injection",
        "url-tool-control",
        "internal-api",
    ]
    assert first.campaign_mode_constraint == "none"
    assert first.chain_state == "hypothesized-not-validated"
    assert first.capability_granted is False
    assert first.execution_authorized is False
    assert first.claim_replay_authorized is False
    assert first.finding_confirmed is False


@pytest.mark.parametrize("mode", list(CampaignMode))
def test_chain003_compiles_the_same_closed_contract_for_every_campaign_mode(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    mode: CampaignMode,
) -> None:
    campaign = _campaign(sample_campaign, mode)
    mcp_recon = _mcp_recon(tmp_path, campaign)
    internal_recon = _http_recon(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(),
    )
    prompt_id, url_tool_id, internal_api_id = _surface_ids(mcp_recon, internal_recon)

    authority = compile_prompt_url_internal_api_chain(
        campaign,
        mcp_recon,
        internal_recon,
        prompt_surface_id=prompt_id,
        url_tool_surface_id=url_tool_id,
        internal_api_surface_id=internal_api_id,
    )

    assert authority.contract == registered_prompt_url_internal_api_chain_contract()
    assert [stage.execution_state for stage in authority.stages] == [
        "discovered-not-authorized"
    ] * 3
    assert authority.stages[0].surface.target_id == authority.stages[1].surface.target_id
    assert authority.stages[2].surface.target_id == "internal-api-spec"
    assert authority.surface_evidence_only is True
    assert authority.execution_authorized is False
    assert authority.finding_confirmed is False
    assert (
        verify_prompt_url_internal_api_chain(
            authority,
            campaign,
            mcp_recon,
            internal_recon,
        )
        == authority
    )


def test_chain003_rejects_generic_tool_and_route_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    mcp_recon = _mcp_recon(tmp_path, campaign)
    internal_recon = _http_recon(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(),
    )
    prompt_id, _, _ = _surface_ids(mcp_recon, internal_recon)
    generic_url_tools = [
        surface
        for surface in mcp_recon.surface_set.surfaces
        if isinstance(surface.locator, MCPToolSurfaceLocator)
        and surface.locator.tool_name == "inspect_url"
    ]
    routes = [
        surface
        for surface in internal_recon.surface_set.surfaces
        if isinstance(surface.locator, HTTPRouteSurfaceLocator)
        and surface.locator.path_template == "/internal/status"
    ]
    assert len(generic_url_tools) == len(routes) == 1

    with pytest.raises(ModeNeutralURLAttackChainError):
        compile_prompt_url_internal_api_chain(
            campaign,
            mcp_recon,
            internal_recon,
            prompt_surface_id=prompt_id,
            url_tool_surface_id=generic_url_tools[0].surface_id,
            internal_api_surface_id=routes[0].surface_id,
        )


def test_internal_api_recon_fails_closed_without_exact_boolean_declaration(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)

    with pytest.raises(ReconWaveError, match="lacks a required Surface kind"):
        _http_recon(
            tmp_path,
            campaign,
            monkeypatch,
            _openapi_document(internal=False),
        )

    with pytest.raises(ValueError, match="trusted Surface adapter rejected"):
        _http_recon(
            tmp_path,
            campaign,
            monkeypatch,
            _openapi_document(internal="true"),
        )


def test_chain003_rejects_authority_forgery_and_tampered_projection(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    mcp_recon = _mcp_recon(tmp_path, campaign)
    internal_recon = _http_recon(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(),
    )
    prompt_id, url_tool_id, internal_api_id = _surface_ids(mcp_recon, internal_recon)
    authority = compile_prompt_url_internal_api_chain(
        campaign,
        mcp_recon,
        internal_recon,
        prompt_surface_id=prompt_id,
        url_tool_surface_id=url_tool_id,
        internal_api_surface_id=internal_api_id,
    )
    payload = authority.model_dump(mode="json", by_alias=True)
    payload["executionAuthorized"] = True
    with pytest.raises(ValidationError):
        ModeNeutralURLAttackChainAuthority.model_validate(payload)

    substituted_internal_recon = _http_recon(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(),
    )
    with pytest.raises(ModeNeutralURLAttackChainError):
        verify_prompt_url_internal_api_chain(
            authority,
            campaign,
            mcp_recon,
            substituted_internal_recon,
        )

    artifact = internal_recon.projection_run_path / internal_recon.publication.artifact_path
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    with pytest.raises(ModeNeutralURLAttackChainError):
        verify_prompt_url_internal_api_chain(
            authority,
            campaign,
            mcp_recon,
            internal_recon,
        )
