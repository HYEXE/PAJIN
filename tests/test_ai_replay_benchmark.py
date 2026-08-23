from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ai_analysis_admission import _gate, _provider_preparation, _source_inputs
from test_existing_capability_rollout import (
    _capability_worker_job,
    _redteam_llm_worker_fixture,
)
from test_kisa_replay import TranscriptWorker, _trusted_docker_backend
from test_profile_validation_evidence import (
    _campaign,
    _KISAControlContrastWorker,
    _tools,
    _trusted_backend,
)

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.control_plane.executors import CampaignJobExecutor, CapabilityGraphCampaignJobInput
from pajin.discovery.validation_depth import ValidationDepth
from pajin.modes.ai_redteam import (
    KISACandidateProducer,
    KISAPlannerRuntime,
    KISAReplayCoordinator,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.validation_controls import KISAValidationControlCoordinator
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.ai_replay_benchmark import (
    AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION,
    AIAnalysisReplayBenchmarkBinding,
    AIReplayBenchmarkError,
    bind_ai_analysis_replay_controls_and_benchmark,
)
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


@pytest.mark.asyncio
async def test_ai001d_binds_fresh_replay_controls_and_benchmark_without_authority(
    tmp_path: Path,
) -> None:
    _, runtime, raw_job = _redteam_llm_worker_fixture(tmp_path / "ai-source")
    ai_worker = TranscriptWorker([True])
    executor = CampaignJobExecutor(
        output_root=tmp_path / "unused-local-runs",
        worker=_trusted_docker_backend(ai_worker),
        capability_deployment=runtime,
    )
    await executor.execute(_capability_worker_job(raw_job))
    job = CapabilityGraphCampaignJobInput.model_validate(raw_job)
    preparation = _provider_preparation(runtime, job)
    gate, graph = _gate(runtime)
    inputs = _source_inputs(runtime, job, preparation)
    admission = gate.admit(inputs, gate.prepare_candidate(inputs, graph))

    campaign = _campaign()
    tools = _tools()
    backend = _trusted_backend(_KISAControlContrastWorker())
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    source = await MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=2)),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "kisa-source",
    ).run(campaign, budget=budget, rate_limits=rate_limits)
    candidate_id = source.validation.candidates[0].candidate_id
    replay = await KISAReplayCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "kisa-replay",
        repetitions=2,
        required_successes=2,
    ).reproduce(
        campaign,
        source.run_path,
        budget=budget,
        rate_limits=rate_limits,
    )
    controls = await KISAValidationControlCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "kisa-controls",
    ).execute(
        campaign,
        source.run_path,
        budget=budget,
        rate_limits=rate_limits,
    )

    binding = bind_ai_analysis_replay_controls_and_benchmark(
        inputs,
        admission,
        graph_store=runtime.graph_store,
        kisa_source_run_path=source.run_path,
        candidate_id=candidate_id,
        replay_outcome=replay,
        control_outcome=controls,
    )
    retry = bind_ai_analysis_replay_controls_and_benchmark(
        inputs,
        admission,
        graph_store=runtime.graph_store,
        kisa_source_run_path=source.run_path,
        candidate_id=candidate_id,
        replay_outcome=replay,
        control_outcome=controls,
    )

    assert binding.api_version == AI_ANALYSIS_REPLAY_BENCHMARK_API_VERSION
    assert retry == binding
    assert binding.scenario_id == "kisa.model.system-prompt-disclosure"
    assert binding.threat_class == "M03"
    assert (
        binding.profile_validation.achieved_depth
        is ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY
    )
    assert binding.profile_validation.control_evidence is not None
    assert binding.redteam_profile.false_positive_measurement.value == "required"
    assert binding.redteam_profile.replay_measurement.value == "required"
    assert tuple(item.value for item in binding.ground_truth_classes) == (
        "known-positive",
        "negative-control",
    )
    assert binding.ground_truth_case_bound is False
    assert binding.benchmark_measurement_observed is False
    assert binding.ai_observation_confirmed is False
    assert len(ai_worker.jobs) == 1
    assert all(
        value is False
        for key, value in binding.model_dump(mode="python").items()
        if key.endswith("authority") or key.endswith("authorized")
    )

    substituted = binding.model_dump(mode="json", by_alias=True)
    substituted["bindingId"] = ""
    substituted["bindingDigest"] = ""
    substituted["scenarioId"] = "kisa.model.jailbreak-policy-bypass"
    with pytest.raises(ValidationError, match="coordinates differ"):
        AIAnalysisReplayBenchmarkBinding.model_validate(substituted)

    escalated = binding.model_dump(mode="json", by_alias=True)
    escalated["executionAuthorized"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        AIAnalysisReplayBenchmarkBinding.model_validate(escalated)

    control_path = controls.run_paths[candidate_id] / "control-plan.json"
    control_path.write_text("{}", encoding="utf-8")
    with pytest.raises(AIReplayBenchmarkError, match="failed closed"):
        bind_ai_analysis_replay_controls_and_benchmark(
            inputs,
            admission,
            graph_store=runtime.graph_store,
            kisa_source_run_path=source.run_path,
            candidate_id=candidate_id,
            replay_outcome=replay,
            control_outcome=controls,
        )
