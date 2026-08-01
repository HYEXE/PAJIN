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
    DeterministicWalkingObservationReplanCompiler,
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIRAGSurfaceAdapter,
    HTTPRAGInjectionReconPlanner,
    MCPAuthorizationObservationEvidence,
    MCPBoundarySurfaceAdapter,
    MCPToolAuthorizationHypothesisAuthority,
    MCPToolAuthorizationHypothesisError,
    MCPToolAuthorizationHypothesisRunner,
    MCPToolAuthorizationReconPlanner,
    MCPToolSurfaceLocator,
    RAGInjectionHypothesisRunner,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
    WalkingGraphRelationship,
    WalkingObservationReplanAuthority,
    WalkingObservationReplanError,
    WalkingObservationReplanRunner,
    load_walking_observation_replan_authority,
    mcp_tool_authorization_rule,
    walking_observation_replan_rule,
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


def _nested_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _nested_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _nested_keys(child)}
    return set()


def _different_paths(left: object, right: object, path: str = "") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict) and isinstance(right, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            paths.extend(_different_paths(left.get(key), right.get(key), f"{path}.{key}"))
        return paths
    if isinstance(left, list) and isinstance(right, list):
        paths = []
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=False)):
            paths.extend(_different_paths(left_item, right_item, f"{path}[{index}]"))
        if len(left) != len(right):
            paths.append(f"{path}.length")
        return paths
    return [] if left == right else [path]


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


def _mcp_outcome(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
):
    rag = _rag_outcome(tmp_path, campaign, monkeypatch)
    mcp = _mcp_recon(tmp_path, campaign)
    return MCPToolAuthorizationHypothesisRunner(
        compiler=_compiler(mcp),
        output_root=tmp_path,
    ).run(campaign, rag, mcp)


def _replan_compiler(source) -> DeterministicWalkingObservationReplanCompiler:
    return DeterministicWalkingObservationReplanCompiler(
        rule=walking_observation_replan_rule(
            source_hypothesis_rule_id=source.hypotheses[0].rule_id,
        )
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
    (outcome.run_path / outcome.artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(WalkingObservationReplanError, match="not sealed and valid"):
        load_walking_observation_replan_authority(campaign, outcome)


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


def test_walking_observation_replan_admits_state_and_selects_new_plan(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    source = _mcp_outcome(tmp_path, campaign, monkeypatch)
    compiler = _replan_compiler(source)
    evidence = compiler.evidence(campaign, source)
    baseline = compiler.baseline_state_digest(campaign, source)

    first = compiler.compile(
        campaign,
        source,
        evidence,
        expected_previous_state_digest=baseline,
    )
    second = compiler.compile(
        campaign.model_copy(deep=True),
        source,
        evidence,
        expected_previous_state_digest=baseline,
    )
    first_payload = first.model_dump(mode="json", by_alias=True)
    second_payload = second.model_dump(mode="json", by_alias=True)
    assert first_payload == second_payload, _different_paths(first_payload, second_payload)
    assert first.observation.admission_state == "admitted"
    assert first.plan.action == "request-independent-approval"
    assert first.plan.execution_state == "proposed-not-authorized"
    assert first.plan.plan_state_digest != baseline
    assert {item.relation for item in first.graph.relationships} == {
        "supports",
        "enables",
        "depends-on",
    }
    assert first.plan.required_capability == source.hypotheses[0].capability.reference()

    outcome = WalkingObservationReplanRunner(
        compiler=compiler,
        output_root=tmp_path,
    ).run(
        campaign,
        source,
        evidence,
        expected_previous_state_digest=baseline,
    )
    assert verify_run_integrity(outcome.run_path).valid
    assert load_walking_observation_replan_authority(campaign, outcome) == first
    artifact = json.loads((outcome.run_path / outcome.artifact_path).read_text("utf-8"))
    assert artifact == first.model_dump(mode="json", by_alias=True)
    serialized = json.dumps(artifact, sort_keys=True)
    assert "ToolRequest" not in serialized
    assert "arguments" not in _nested_keys(artifact)
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


def test_walking_observation_replan_rejects_forged_evidence_and_source_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    source = _mcp_outcome(tmp_path, campaign, monkeypatch)
    compiler = _replan_compiler(source)
    evidence = compiler.evidence(campaign, source)
    baseline = compiler.baseline_state_digest(campaign, source)
    payload = evidence.model_dump(mode="json", by_alias=True)
    payload.update(
        {
            "evidenceId": "",
            "evidenceDigest": "",
            "sourceRootDigest": "0" * 64,
        }
    )
    forged = MCPAuthorizationObservationEvidence.model_validate(payload)

    with pytest.raises(WalkingObservationReplanError, match="differs from sealed"):
        compiler.compile(
            campaign,
            source,
            forged,
            expected_previous_state_digest=baseline,
        )

    substituted = replace(source, run_id="another-run")
    with pytest.raises(WalkingObservationReplanError, match="not sealed and valid"):
        compiler.compile(
            campaign,
            substituted,
            evidence,
            expected_previous_state_digest=baseline,
        )

    forged_hypothesis = source.hypotheses[0].model_copy(
        update={"hypothesis_id": "mcp-tool-authorization-hypothesis_" + "0" * 64},
        deep=True,
    )
    with pytest.raises(WalkingObservationReplanError, match="differs from sealed"):
        compiler.compile(
            campaign,
            replace(source, hypotheses=(forged_hypothesis,)),
            evidence,
            expected_previous_state_digest=baseline,
        )


def test_walking_observation_replan_blocks_stale_repeated_and_cyclic_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    source = _mcp_outcome(tmp_path, campaign, monkeypatch)
    compiler = _replan_compiler(source)
    evidence = compiler.evidence(campaign, source)
    baseline = compiler.baseline_state_digest(campaign, source)

    with pytest.raises(WalkingObservationReplanError, match="stale"):
        compiler.compile(
            campaign,
            source,
            evidence,
            expected_previous_state_digest="0" * 64,
        )

    prior_outcome = WalkingObservationReplanRunner(
        compiler=compiler,
        output_root=tmp_path,
    ).run(
        campaign,
        source,
        evidence,
        expected_previous_state_digest=baseline,
    )
    first = prior_outcome.authority
    with pytest.raises(WalkingObservationReplanError, match="cycle or repeated"):
        compiler.compile(
            campaign,
            source,
            evidence,
            expected_previous_state_digest=first.plan.plan_state_digest,
            prior_outcome=prior_outcome,
        )

    payload = first.model_dump(mode="json", by_alias=True)
    payload.update(
        {
            "authorityId": "",
            "authorityDigest": "",
            "statePath": [baseline, "1" * 64, baseline, first.plan.plan_state_digest],
        }
    )
    with pytest.raises(ValueError, match="cycle or repeated"):
        WalkingObservationReplanAuthority.model_validate(payload)


def test_walking_observation_graph_rejects_noncanonical_relationship_topology(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    source = _mcp_outcome(tmp_path, campaign, monkeypatch)
    compiler = _replan_compiler(source)
    evidence = compiler.evidence(campaign, source)
    baseline = compiler.baseline_state_digest(campaign, source)
    authority = compiler.compile(
        campaign,
        source,
        evidence,
        expected_previous_state_digest=baseline,
    )
    payload = authority.model_dump(mode="json", by_alias=True)
    payload.update({"authorityId": "", "authorityDigest": ""})
    relationship = payload["graph"]["relationships"][0]
    relationship.update(
        {
            "relationshipId": "",
            "relationshipDigest": "",
            "relation": "contradicts",
        }
    )
    mutated = WalkingGraphRelationship.model_validate(relationship)
    payload["graph"]["relationships"][0] = mutated.model_dump(mode="json", by_alias=True)
    payload["graph"]["relationships"].sort(key=lambda item: item["relationshipId"])
    payload["graph"].update({"snapshotId": "", "snapshotDigest": ""})

    with pytest.raises(ValueError, match="topology is malformed"):
        WalkingObservationReplanAuthority.model_validate(payload)


@pytest.mark.parametrize("expansion", ["scope", "snapshot", "capability"])
def test_walking_observation_replan_authority_rejects_expansion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    expansion: str,
) -> None:
    campaign = _campaign(sample_campaign)
    source = _mcp_outcome(tmp_path, campaign, monkeypatch)
    compiler = _replan_compiler(source)
    evidence = compiler.evidence(campaign, source)
    baseline = compiler.baseline_state_digest(campaign, source)
    authority = compiler.compile(
        campaign,
        source,
        evidence,
        expected_previous_state_digest=baseline,
    )
    payload = authority.model_dump(mode="json", by_alias=True)
    payload.update({"authorityId": "", "authorityDigest": ""})
    match = "Campaign authority differs"
    if expansion == "scope":
        payload["campaignManifest"]["spec"]["targets"][0]["endpoint"] = (
            "https://expanded.example.invalid"
        )
    else:
        payload["plan"].update({"planId": "", "planDigest": "", "planStateDigest": ""})
        match = "Plan expands or differs"
        if expansion == "snapshot":
            payload["plan"]["mcpSurfaceSnapshotDigest"] = "0" * 64
        else:
            payload["plan"]["requiredCapability"]["capabilityDigest"] = "0" * 64

    with pytest.raises(ValueError, match=match):
        WalkingObservationReplanAuthority.model_validate(payload)


def test_walking_observation_replan_rejects_mutated_sealed_artifact(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign)
    source = _mcp_outcome(tmp_path, campaign, monkeypatch)
    compiler = _replan_compiler(source)
    evidence = compiler.evidence(campaign, source)
    baseline = compiler.baseline_state_digest(campaign, source)
    (source.run_path / source.artifact_path).write_text("[]", encoding="utf-8")

    with pytest.raises(WalkingObservationReplanError, match="not sealed and valid"):
        compiler.compile(
            campaign,
            source,
            evidence,
            expected_previous_state_digest=baseline,
        )
