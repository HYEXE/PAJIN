from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_existing_capability_rollout import (
    _capability_worker_job,
    _CountingSimulatedWorker,
    _redteam_llm_worker_fixture,
    _redteam_mcp_worker_fixture,
)
from test_kisa_replay import TranscriptWorker, _trusted_docker_backend

from pajin.capabilities.ai_analysis import (
    AIAnalysisBudgetCeiling,
    AIReadOnlyAnalysisPreparation,
    bind_ai_read_only_analysis,
    prepare_ai_read_only_analysis,
    registered_ai_read_only_analysis_capability_bindings,
)
from pajin.control_plane.executors import (
    CampaignJobExecutor,
    CapabilityGraphCampaignJobInput,
)
from pajin.control_plane.redteam_profiles import REDTEAM_LLM_RAG_PROFILE
from pajin.discovery import (
    AISurfaceClass,
    MCPServerSurfaceLocator,
    http_rag_surface_locator,
    http_route_surface_locator,
    typed_ai_security_surface,
)
from pajin.graph import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphNodeKind,
    GraphProducerRegistry,
    TrustedGraphLineageRegistry,
)
from pajin.providers.models import ProviderRegistration
from pajin.workflow.ai_analysis_admission import (
    AIAnalysisGraphAdmissionBinding,
    AIAnalysisObservationAdmissionError,
    AIAnalysisObservationAdmissionGate,
    AIAnalysisObservationCandidate,
    AIAnalysisObservationSourceInputs,
    ai_analysis_observation_producer_registration,
)

_AUTHORITY_ID = "pajin.graph.capability-worker-admission"
_AUTHORITY_DIGEST = "a" * 64
_MODEL_REVISION = "2026-08-24-admission-model-sha256"


def _provider(endpoint: str) -> ProviderRegistration:
    return ProviderRegistration(
        provider_id="analysis-provider",
        endpoint=endpoint,
        model="analysis-model-2026-08",
        secret_ref="provider/analysis/api-key",
        allow_streaming=False,
        allowed_function_tools=set(),
        lease_ttl_seconds=30,
        input_cost_per_million_usd=2.5,
        output_cost_per_million_usd=7.5,
        allow_private_networks=True,
    )


def _static_binding(capability_id: str):
    return next(
        item
        for item in registered_ai_read_only_analysis_capability_bindings()
        if item.capability.capability.capability_id == capability_id
    )


def _provider_preparation(
    runtime,
    job: CapabilityGraphCampaignJobInput,
) -> AIReadOnlyAnalysisPreparation:
    provider = _provider(job.request.target)
    rag_surface = None
    if job.profile == REDTEAM_LLM_RAG_PROFILE:
        scheme, rest = job.request.target.split("://", maxsplit=1)
        host, path = rest.split("/", maxsplit=1)
        rag_surface = typed_ai_security_surface(
            locator=http_rag_surface_locator(
                route=http_route_surface_locator(
                    base_url=f"{scheme}://{host}",
                    path_template=f"/{path}",
                    method="POST",
                    request_content_types=("application/json",),
                    response_content_types=("application/json",),
                ),
                boundary="retrieval",
                index_ids=("assessment-memory",),
            )
        )
    binding = bind_ai_read_only_analysis(
        capability=_static_binding(job.proposal.capability.capability_id).reference(),
        budget=AIAnalysisBudgetCeiling(
            requestUnits=job.proposal.reservation.request_units,
            maxInputTokens=4096,
            maxOutputTokens=1024,
            maxTotalTokens=5120,
            maxCostMicroUsd=250_000,
            providerUsageApplicable=True,
        ),
        provider_registration=provider,
        model_revision=_MODEL_REVISION,
        rag_surface=rag_surface,
    )
    return prepare_ai_read_only_analysis(
        activation=runtime.activation,
        release=job.release,
        binding=binding,
        request=job.request,
        provider_registration=provider,
    )


def _mcp_preparation(
    runtime,
    job: CapabilityGraphCampaignJobInput,
) -> AIReadOnlyAnalysisPreparation:
    mcp_surface = typed_ai_security_surface(
        locator=MCPServerSurfaceLocator(
            server_id="demo-security",
            protocol_version="2025-06-18",
            capabilities=("tools",),
        )
    )
    binding = bind_ai_read_only_analysis(
        capability=_static_binding(job.proposal.capability.capability_id).reference(),
        budget=AIAnalysisBudgetCeiling(
            requestUnits=1,
            maxInputTokens=0,
            maxOutputTokens=0,
            maxTotalTokens=0,
            maxCostMicroUsd=0,
            providerUsageApplicable=False,
        ),
        mcp_surface=mcp_surface,
    )
    return prepare_ai_read_only_analysis(
        activation=runtime.activation,
        release=job.release,
        binding=binding,
        request=job.request,
    )


def _gate(runtime) -> tuple[AIAnalysisObservationAdmissionGate, AIAnalysisGraphAdmissionBinding]:
    lineages = TrustedGraphLineageRegistry()
    authority = GraphAdmissionAuthority(
        campaign_id=runtime.graph_store.campaign_id,
        authority_id=_AUTHORITY_ID,
        authority_digest=_AUTHORITY_DIGEST,
        producers=GraphProducerRegistry([ai_analysis_observation_producer_registration()]),
        lineage_verifier=lineages,
        event_log=runtime.graph_store.event_log,
        clock=lambda: datetime.now(UTC) + timedelta(seconds=1),
    )
    gate = AIAnalysisObservationAdmissionGate(
        graph_store=runtime.graph_store,
        graph_admission=authority,
        trusted_lineages=lineages,
    )
    permit = runtime.graph_store.permit_store.permits()[0]
    return gate, AIAnalysisGraphAdmissionBinding(
        snapshot=permit.snapshot,
        authorityId=_AUTHORITY_ID,
        authorityDigest=_AUTHORITY_DIGEST,
    )


def _source_inputs(
    runtime,
    job: CapabilityGraphCampaignJobInput,
    preparation: AIReadOnlyAnalysisPreparation,
) -> AIAnalysisObservationSourceInputs:
    return AIAnalysisObservationSourceInputs(
        run_path=(
            Path(runtime.deployment.run_root)
            / runtime.deployment.campaign.metadata.name
            / job.proposal.run_id
        ),
        expected_run_id=job.proposal.run_id,
        preparation=preparation,
        job=job,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_case", ["model-tool", "model-rag-tool", "mcp-tool"])
async def test_sealed_ai_result_admits_only_cross_surface_observation_and_evidence(
    tmp_path: Path,
    surface_case: str,
) -> None:
    if surface_case == "mcp-tool":
        _, runtime, raw_job = _redteam_mcp_worker_fixture(tmp_path)
        worker = _CountingSimulatedWorker()
        executor = CampaignJobExecutor(
            output_root=tmp_path / "unused-local-runs",
            worker=worker,
            capability_deployment=runtime,
        )
    else:
        scenario_id = (
            "kisa.agent.memory-poisoning-persistence"
            if surface_case == "model-rag-tool"
            else "kisa.model.system-prompt-disclosure"
        )
        profile = REDTEAM_LLM_RAG_PROFILE if surface_case == "model-rag-tool" else "redteam-llm-v1"
        _, runtime, raw_job = _redteam_llm_worker_fixture(
            tmp_path,
            scenario_id=scenario_id,
            profile=profile,
        )
        worker = TranscriptWorker([True])
        executor = CampaignJobExecutor(
            output_root=tmp_path / "unused-local-runs",
            worker=_trusted_docker_backend(worker),
            capability_deployment=runtime,
        )
    job = CapabilityGraphCampaignJobInput.model_validate(raw_job)
    preparation = (
        _mcp_preparation(runtime, job)
        if surface_case == "mcp-tool"
        else _provider_preparation(runtime, job)
    )

    result = await executor.execute(_capability_worker_job(raw_job))
    gate, graph = _gate(runtime)
    inputs = _source_inputs(runtime, job, preparation)
    candidate = gate.prepare_candidate(inputs, graph)
    admitted = gate.admit(inputs, candidate)
    retry = gate.admit(inputs, candidate)

    assert result.result["toolSuccess"] is True
    assert (
        tuple(item.surface_class for item in candidate.surfaces)
        == {
            "model-tool": (AISurfaceClass.MODEL, AISurfaceClass.TOOL),
            "model-rag-tool": (
                AISurfaceClass.MODEL,
                AISurfaceClass.RAG,
                AISurfaceClass.TOOL,
            ),
            "mcp-tool": (AISurfaceClass.MCP, AISurfaceClass.TOOL),
        }[surface_case]
    )
    assert candidate.domain_observation_type == "ai.behavior-observation"
    assert admitted.state == "registered-not-authorized"
    assert admitted.graph_event.decision is GraphAdmissionDecision.ADMITTED
    assert [node.kind for node in admitted.graph_event.admitted_nodes].count(
        GraphNodeKind.OBSERVATION.value
    ) == 1
    assert [node.kind for node in admitted.graph_event.admitted_nodes].count(
        GraphNodeKind.EVIDENCE.value
    ) == 2
    assert all(
        node.kind not in {GraphNodeKind.SURFACE.value, GraphNodeKind.HYPOTHESIS.value}
        for node in admitted.graph_event.admitted_nodes
    )
    assert retry == admitted
    if surface_case == "mcp-tool":
        assert worker.calls == 1
    else:
        assert len(worker.jobs) == 1
    assert all(
        value is False
        for key, value in admitted.model_dump(mode="python").items()
        if key.endswith("authority") or key.endswith("authorized")
    )

    substituted = admitted.model_dump(mode="json", by_alias=True)
    substituted["admissionId"] = ""
    substituted["admissionDigest"] = ""
    substituted["graphEvent"]["eventId"] = ""
    substituted["graphEvent"]["eventDigest"] = ""
    substituted["graphEvent"]["agentId"] = "agent:foreign-observation-admission"
    with pytest.raises(ValidationError, match="Observation/Evidence authority"):
        type(admitted).model_validate(substituted)


@pytest.mark.asyncio
async def test_ai_observation_rejects_grant_substitution_and_candidate_authority(
    tmp_path: Path,
) -> None:
    _, runtime, raw_job = _redteam_mcp_worker_fixture(tmp_path)
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=_CountingSimulatedWorker(),
        capability_deployment=runtime,
    )
    await executor.execute(_capability_worker_job(raw_job))
    job = CapabilityGraphCampaignJobInput.model_validate(raw_job)
    preparation = _mcp_preparation(runtime, job)
    gate, graph = _gate(runtime)
    inputs = _source_inputs(runtime, job, preparation)
    candidate = gate.prepare_candidate(inputs, graph)

    mutated = candidate.model_dump(mode="json", by_alias=True)
    mutated["toolSelectionAuthorized"] = True
    with pytest.raises(ValidationError, match="authority flags"):
        AIAnalysisObservationCandidate.model_validate(mutated)

    foreign_job = job.model_copy(
        update={"grant": job.grant.model_copy(update={"grant_id": "grant_foreign"})}
    )
    with pytest.raises(AIAnalysisObservationAdmissionError, match="evidence differs"):
        gate.prepare_candidate(
            _source_inputs(runtime, foreign_job, preparation),
            graph,
        )


@pytest.mark.asyncio
async def test_ai_observation_rejects_tampered_sealed_tool_evidence(tmp_path: Path) -> None:
    _, runtime, raw_job = _redteam_mcp_worker_fixture(tmp_path)
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=_CountingSimulatedWorker(),
        capability_deployment=runtime,
    )
    await executor.execute(_capability_worker_job(raw_job))
    job = CapabilityGraphCampaignJobInput.model_validate(raw_job)
    preparation = _mcp_preparation(runtime, job)
    gate, graph = _gate(runtime)
    inputs = _source_inputs(runtime, job, preparation)
    evidence_path = inputs.run_path / "evidence" / f"{job.request.request_id}.json"
    evidence_path.write_bytes(evidence_path.read_bytes() + b" ")

    with pytest.raises(AIAnalysisObservationAdmissionError, match="source authority"):
        gate.prepare_candidate(inputs, graph)
