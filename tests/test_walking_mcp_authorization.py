from __future__ import annotations

import asyncio
import json
from base64 import b64encode
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.capabilities.adapters import (
    ToolCapabilityRegistration,
    capability_registry_from_tools,
)
from pajin.capabilities.models import CapabilityMaturity, CapabilitySideEffectClass
from pajin.discovery import (
    DeterministicMCPToolAuthorizationHypothesisCompiler,
    DeterministicRAGInjectionHypothesisCompiler,
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIRAGSurfaceAdapter,
    HTTPRAGInjectionReconPlanner,
    MCPBoundarySurfaceAdapter,
    MCPToolAuthorizationHypothesisAuthority,
    MCPToolAuthorizationHypothesisError,
    MCPToolAuthorizationHypothesisRunner,
    MCPToolAuthorizationReconPlanner,
    MCPToolSurfaceLocator,
    RAGInjectionHypothesisRunner,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
    mcp_tool_authorization_rule,
)
from pajin.domain.models import CampaignManifest, ToolRiskTier
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import load_verified_run_events, verify_run_integrity
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
from pajin.tools.mcp import (
    MCPToolRegistration,
    RegisteredMCPTool,
    demo_mcp_discovery_tool,
)

HTTP_TARGET = "https://staging.example.invalid/api/openapi.json"
MCP_TARGET = "https://staging.example.invalid/api/mcp"


def _campaign(sample_campaign: CampaignManifest) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["targets"][0]["endpoint"] = HTTP_TARGET
    mcp_target = dict(payload["spec"]["targets"][0])
    mcp_target.update({"id": "staging-mcp", "endpoint": MCP_TARGET})
    payload["spec"]["targets"].append(mcp_target)
    return CampaignManifest.model_validate(payload)


def _openapi_document() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/documents": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["document"],
                                    "properties": {
                                        "document": {"type": "string", "format": "binary"}
                                    },
                                }
                            }
                        },
                    },
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "corpus-ingest",
                        "corpusIds": ["knowledge-base"],
                        "indexIds": [],
                    },
                    "responses": {"202": {"description": "accepted"}},
                }
            }
        },
    }


def _docker_backend(monkeypatch: pytest.MonkeyPatch) -> DockerWorkerBackend:
    body = json.dumps(_openapi_document(), separators=(",", ":")).encode()
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
        occurred_at = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(
                {
                    "target": HTTP_TARGET,
                    "status": 200,
                    "contentType": "application/json",
                    "bodyPreview": body.decode(),
                    "bodySha256": body_digest,
                    "responseBodyBase64": b64encode(body).decode("ascii"),
                }
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
                            "target": audit_http_target(HTTP_TARGET),
                            "targetSha256": http_target_sha256(HTTP_TARGET),
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


def _rag_outcome(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
):
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIRAGSurfaceAdapter(tool=tool, allowed_methods=("GET", "POST"))
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[reference],
    )
    recon = asyncio.run(
        SingleReconWaveRunner(
            planner=HTTPRAGInjectionReconPlanner(
                tool=tool,
                target_id=campaign.spec.targets[0].id,
                adapter_reference=reference,
            ),
            producer=producer,
            tools=tools,
            policy=PolicyEngine(),
            worker=_docker_backend(monkeypatch),
            output_root=tmp_path,
        ).run(campaign)
    )
    return RAGInjectionHypothesisRunner(
        compiler=DeterministicRAGInjectionHypothesisCompiler(),
        output_root=tmp_path,
    ).run(campaign, recon)


def _mcp_recon(tmp_path: Path, campaign: CampaignManifest):
    tools = ToolRegistry()
    tool = demo_mcp_discovery_tool()
    tools.register(tool)
    adapter = MCPBoundarySurfaceAdapter(tool=tool)
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[reference],
    )
    return asyncio.run(
        SingleReconWaveRunner(
            planner=MCPToolAuthorizationReconPlanner(
                tool=tool,
                target_id=campaign.spec.targets[1].id,
                adapter_reference=reference,
            ),
            producer=producer,
            tools=tools,
            policy=PolicyEngine(),
            worker=SimulatedWorkerBackend(),
            output_root=tmp_path,
        ).run(campaign)
    )


def _compiler(mcp_recon, *, schema_digest: str | None = None, approval: bool = True):
    locator = next(
        surface.locator
        for surface in mcp_recon.surface_set.surfaces
        if isinstance(surface.locator, MCPToolSurfaceLocator)
        and surface.locator.tool_name == "inspect_text"
    )
    tools = ToolRegistry()
    tools.register(
        RegisteredMCPTool(
            MCPToolRegistration(
                tool_id="mcp.demo-security.rag-document-probe",
                server_id="demo-security",
                remote_tool_name="inspect_text",
                description="Probe RAG document influence on one MCP Tool",
                risk_tier=ToolRiskTier.T1,
            )
        )
    )
    capabilities = capability_registry_from_tools(
        tools,
        [
            ToolCapabilityRegistration(
                capabilityId="rag-document-probe",
                capabilityVersion="1.0.0",
                toolId="mcp.demo-security.rag-document-probe",
                domain="ai-redteam",
                maturity=CapabilityMaturity.EXPERIMENTAL,
                supportedSurfaceTypes=("mcp-tool",),
                threatClasses=("mcp-tool-authorization-failure",),
                preconditions=("sealed-rag-injection-hypothesis",),
                parameterSchemaDigest=schema_digest or locator.input_schema_digest,
                sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
                approvalRequired=approval,
                cleanupRequired=False,
            )
        ],
    )
    definition = capabilities.definitions()[0]
    return DeterministicMCPToolAuthorizationHypothesisCompiler(
        tools=tools,
        capabilities=capabilities,
        rule=mcp_tool_authorization_rule(
            server_id="demo-security",
            tool_name="inspect_text",
            capability=definition.reference(),
        ),
    )


def test_mcp_tool_authorization_recon_binds_disc_003d_and_surface_kinds(
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _campaign(sample_campaign)
    tools = ToolRegistry()
    tool = demo_mcp_discovery_tool()
    tools.register(tool)
    adapter = MCPBoundarySurfaceAdapter(tool=tool)
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    plan = MCPToolAuthorizationReconPlanner(
        tool=tool,
        target_id=campaign.spec.targets[1].id,
        adapter_reference=reference,
    ).plan(campaign)

    assert plan.adapter_reference == reference
    assert plan.required_surface_kinds == ("mcp-server", "mcp-tool")
    assert plan.request.arguments == {}
    assert plan.request.target == MCP_TARGET


def test_walking_mcp_authorization_seals_registered_but_non_executable_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    rag = _rag_outcome(tmp_path, campaign, monkeypatch)
    mcp = _mcp_recon(tmp_path, campaign)
    compiler = _compiler(mcp)

    first = compiler.compile(campaign, rag, mcp)
    assert first == compiler.compile(campaign.model_copy(deep=True), rag, mcp)
    hypothesis = first[0]
    assert hypothesis.execution_state == "registered-not-authorized"
    assert hypothesis.rag_dependency.hypothesis.hypothesis_id == rag.hypotheses[0].hypothesis_id
    assert hypothesis.tool_locator.tool_name == "inspect_text"
    assert hypothesis.capability.capability_id == "rag-document-probe"
    assert hypothesis.capability.approval_required
    assert (
        hypothesis.capability.parameter_schema_digest == hypothesis.tool_locator.input_schema_digest
    )

    outcome = MCPToolAuthorizationHypothesisRunner(
        compiler=compiler,
        output_root=tmp_path,
    ).run(campaign, rag, mcp)
    assert verify_run_integrity(outcome.run_path).valid
    artifact = json.loads((outcome.run_path / outcome.artifact_path).read_text("utf-8"))
    assert artifact == [hypothesis.model_dump(mode="json", by_alias=True)]
    assert "request" not in artifact[0]
    events = load_verified_run_events(outcome.run_path)
    assert not any(
        event.event_type
        in {
            "capability.issued",
            "capability.activated",
            "action-permit.issued",
            "tool.requested",
            "worker.dispatched",
        }
        for event in events
    )


@pytest.mark.parametrize("failure", ["schema", "approval"])
def test_mcp_authorization_rejects_schema_or_approval_expansion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    campaign = _campaign(sample_campaign)
    rag = _rag_outcome(tmp_path, campaign, monkeypatch)
    mcp = _mcp_recon(tmp_path, campaign)
    compiler = _compiler(
        mcp,
        schema_digest="0" * 64 if failure == "schema" else None,
        approval=failure != "approval",
    )

    with pytest.raises(MCPToolAuthorizationHypothesisError, match="differs"):
        compiler.compile(campaign, rag, mcp)


def test_mcp_authorization_rejects_rag_artifact_and_recon_plan_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    rag = _rag_outcome(tmp_path, campaign, monkeypatch)
    mcp = _mcp_recon(tmp_path, campaign)
    compiler = _compiler(mcp)

    forged_plan = mcp.plan.model_copy(update={"planner_id": "forged.walk.v1"}, deep=True)
    with pytest.raises(MCPToolAuthorizationHypothesisError, match="Plan differs"):
        compiler.compile(campaign, rag, replace(mcp, plan=forged_plan))

    (rag.run_path / rag.artifact_path).write_text("[]", encoding="utf-8")
    with pytest.raises(MCPToolAuthorizationHypothesisError, match="not sealed and valid"):
        compiler.compile(campaign, rag, mcp)


def test_mcp_authorization_authority_rejects_digest_forgery(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    rag = _rag_outcome(tmp_path, campaign, monkeypatch)
    mcp = _mcp_recon(tmp_path, campaign)
    hypothesis = _compiler(mcp).compile(campaign, rag, mcp)[0]
    payload = hypothesis.model_dump(mode="json", by_alias=True)
    payload["hypothesisDigest"] = "0" * 64

    with pytest.raises(ValueError, match="Hypothesis Digest differs"):
        MCPToolAuthorizationHypothesisAuthority.model_validate(payload)
