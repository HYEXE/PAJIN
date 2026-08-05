from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.benchmark.shadow_measurement import WalkingShadowMeasuredBenchmarkRunner
from pajin.domain.models import CampaignManifest
from pajin.runtime.store import load_verified_run_events, verify_run_integrity
from pajin.supervision.benchmark_campaign import (
    SupervisorBenchmarkCampaignPlan,
    SupervisorBenchmarkCampaignPlanError,
    SupervisorBenchmarkCampaignPlanner,
    SupervisorBenchmarkScheduleSource,
    _coordinate_set_digest,
    _manifest_coordinates,
    invoke_supervisor_benchmark_candidate,
    load_supervisor_benchmark_campaign_plan,
)
from pajin.supervision.checkpoint_scheduler import SupervisorCheckpointScheduler
from pajin.supervision.invocation_journal import supervisor_stable_request_id
from tests.test_supervisor_checkpoint_scheduler import (
    TARGET_PROMPT,
    _graph,
    _invocation_environment,
    _policy,
    _runtime,
    _schedule,
)
from tests.test_supervisor_checkpoint_scheduler import (
    _campaign as _supervisor_campaign,
)
from tests.test_walking_mcp_authorization import (
    _campaign as _walking_campaign,
)
from tests.test_walking_mcp_authorization import _walking_shadow_measured_sources


def _sources(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    *,
    statement: str = TARGET_PROMPT,
    draft_transform: Callable[[dict[str, object]], dict[str, object]] | None = None,
):
    campaign = _supervisor_campaign(_walking_campaign(sample_campaign))
    graph_store, _, _, collaboration = _graph(campaign, statement=statement)
    runtime = _runtime(campaign, graph_store, collaboration)
    snapshot_input, binding, provider, configuration = runtime
    policy = _policy()
    schedule = _schedule(
        SupervisorCheckpointScheduler(
            output_root=tmp_path / "schedules",
            budget_policy=policy,
        ),
        runtime,
        campaign,
        collaboration,
        graph_store,
    )
    invoker, journal, authorities, worker, _, _ = _invocation_environment(
        tmp_path,
        campaign,
        provider,
        policy,
        snapshot_input,
        binding,
        configuration,
        collaboration,
        graph_store,
        draft_transform=draft_transform,
    )
    structural, measured = _walking_shadow_measured_sources(
        tmp_path / "walking",
        campaign,
        monkeypatch,
    )
    baseline_source = WalkingShadowMeasuredBenchmarkRunner(
        output_root=tmp_path / "measured-policy"
    ).run(campaign, structural, measured)
    schedule_sources = (
        SupervisorBenchmarkScheduleSource(
            publication=schedule,
            authorities=authorities,
        ),
    )
    return (
        campaign,
        baseline_source,
        schedule_sources,
        invoker,
        journal,
        worker,
    )


def test_supervisor_benchmark_plan_seals_complete_two_arm_coordinate_set(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, _, _, worker = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    outcome = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans").run(
        campaign,
        baseline,
        sources,
    )
    plan = outcome.plan

    assert worker.calls == 0
    assert len(plan.manifest.arms) == 2
    assert len(plan.coordinates) == 2
    assert len(plan.candidate_schedules) == 1
    assert plan.manifest.protocol.max_model_calls == 1
    assert plan.manifest.arms[0] == plan.baseline_source.baseline_manifest.arms[0]
    assert (
        plan.manifest.arms[1].configuration_digest
        == plan.candidate_implementation.implementation_digest
    )
    assert plan.baseline_source.numeric_results_reused is False
    assert plan.numeric_results_reused is False
    assert plan.pre_dispatch_binding_proven is False
    assert plan.proposal_causal_effect_attributed is False
    assert plan.benchmark_comparison_eligible is False
    assert plan.supervisor_activation_eligible is False
    assert plan.execution_authorized is False
    assert [event.event_type for event in load_verified_run_events(outcome.run_path)] == [
        "campaign.started",
        "benchmark.supervisor-campaign-plan.created",
        "campaign.completed",
    ]
    assert verify_run_integrity(outcome.run_path).valid
    assert load_supervisor_benchmark_campaign_plan(campaign, outcome, baseline, sources) == plan

    serialized = json.dumps(plan.model_dump(mode="json", by_alias=True))
    assert TARGET_PROMPT not in serialized
    assert "supervisor-provider-secret" not in serialized
    assert "baselineValue" not in serialized
    assert "candidateValue" not in serialized


def test_supervisor_benchmark_candidate_binds_plan_coordinate_into_tool_request(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, invoker, _, worker = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    planner = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans")
    plan_outcome = planner.run(campaign, baseline, sources)
    coordinate = plan_outcome.plan.candidate_schedules[0].coordinate

    first = asyncio.run(
        invoke_supervisor_benchmark_candidate(
            campaign,
            plan_outcome,
            baseline,
            sources,
            coordinate_id=coordinate.coordinate_id,
            invoker=invoker,
        )
    )
    second = asyncio.run(
        invoke_supervisor_benchmark_candidate(
            campaign,
            plan_outcome,
            baseline,
            sources,
            coordinate_id=coordinate.coordinate_id,
            invoker=invoker,
        )
    )

    assert worker.calls == 1
    assert first.stable_request_id == second.stable_request_id
    assert first.completion == second.completion
    assert first.stable_request_id.startswith("supervisor_")
    assert first.stable_request_id != supervisor_stable_request_id(sources[0].publication)
    assert first.stable_request_id == supervisor_stable_request_id(
        sources[0].publication,
        request_context=first.request_context,
    )
    assert first.completion.publication.receipt.request_context == first.request_context
    assert (
        first.completion.publication.receipt.api_version
        == "pajin.dev/supervisor-invocation-receipt/v1alpha2"
    )
    assert (
        first.completion.publication.receipt.provider_outcome.request_id == first.stable_request_id
    )
    assert (
        first.completion.publication.journal_entry.intent.stable_request_id
        == first.stable_request_id
    )
    assert first.coordinate.coordinate_digest == coordinate.coordinate_digest


def test_supervisor_benchmark_candidate_rejects_foreign_invoker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, _, _, _ = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    plan = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans").run(
        campaign,
        baseline,
        sources,
    )
    coordinate = plan.plan.candidate_schedules[0].coordinate

    class FakeInvoker:
        called = False

        async def invoke(self, *args: object, **kwargs: object) -> object:
            self.called = True
            raise AssertionError("foreign invoker must not be called")

    fake = FakeInvoker()
    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        asyncio.run(
            invoke_supervisor_benchmark_candidate(
                campaign,
                plan,
                baseline,
                sources,
                coordinate_id=coordinate.coordinate_id,
                invoker=fake,  # type: ignore[arg-type]
            )
        )
    assert fake.called is False


def test_supervisor_benchmark_candidate_rejects_cross_plan_and_posthoc_replay(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, invoker, _, worker = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    planner = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans")
    first_plan = planner.run(campaign, baseline, sources)
    second_plan = planner.run(campaign, baseline, sources)
    coordinate = first_plan.plan.candidate_schedules[0].coordinate

    asyncio.run(
        invoke_supervisor_benchmark_candidate(
            campaign,
            first_plan,
            baseline,
            sources,
            coordinate_id=coordinate.coordinate_id,
            invoker=invoker,
        )
    )
    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        asyncio.run(
            invoke_supervisor_benchmark_candidate(
                campaign,
                second_plan,
                baseline,
                sources,
                coordinate_id=coordinate.coordinate_id,
                invoker=invoker,
            )
        )
    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        asyncio.run(
            invoke_supervisor_benchmark_candidate(
                campaign,
                first_plan,
                baseline,
                sources,
                coordinate_id="benchmark-coordinate:" + "9" * 64,
                invoker=invoker,
            )
        )
    assert worker.calls == 1


def test_posthoc_benchmark_binding_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, invoker, _, worker = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    asyncio.run(invoker.invoke(sources[0].publication, sources[0].authorities))
    plan = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans").run(
        campaign,
        baseline,
        sources,
    )
    coordinate = plan.plan.candidate_schedules[0].coordinate

    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        asyncio.run(
            invoke_supervisor_benchmark_candidate(
                campaign,
                plan,
                baseline,
                sources,
                coordinate_id=coordinate.coordinate_id,
                invoker=invoker,
            )
        )
    assert worker.calls == 1


def test_supervisor_benchmark_plan_rejects_scope_authority_and_source_forgery(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, _, _, _ = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    planner = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans")
    outcome = planner.run(campaign, baseline, sources)
    raw = outcome.plan.model_dump(mode="json", by_alias=True)

    mutations: tuple[tuple[str, object], ...] = (
        ("coordinates", raw["coordinates"][:-1]),
        ("candidateSchedules", []),
        ("campaignManifestDigest", "9" * 64),
        ("coordinateSetDigest", "9" * 64),
        ("numericResultsReused", True),
        ("preDispatchBindingProven", True),
        ("proposalCausalEffectAttributed", True),
        ("benchmarkComparisonEligible", True),
        ("supervisorActivationEligible", True),
        ("executionAuthorized", True),
    )
    for field, value in mutations:
        forged = json.loads(json.dumps(raw))
        forged[field] = value
        forged["planId"] = ""
        forged["planDigest"] = ""
        with pytest.raises(ValidationError):
            SupervisorBenchmarkCampaignPlan.model_validate(forged)

    foreign_configuration = json.loads(json.dumps(raw))
    foreign_configuration["manifest"]["arms"][1]["configurationDigest"] = "9" * 64
    foreign_configuration["planId"] = ""
    foreign_configuration["planDigest"] = ""
    with pytest.raises(ValidationError):
        SupervisorBenchmarkCampaignPlan.model_validate(foreign_configuration)

    foreign_walking = json.loads(json.dumps(raw))
    foreign_walking["baselineSource"]["walkingCampaignDigest"] = "9" * 64
    foreign_walking["baselineSource"]["baselineManifest"]["campaignDigest"] = "9" * 64
    foreign_baseline = type(outcome.plan.baseline_source.baseline_manifest).model_validate(
        foreign_walking["baselineSource"]["baselineManifest"]
    )
    foreign_walking["baselineSource"]["baselineManifestDigest"] = foreign_baseline.digest()
    foreign_manifest_raw = foreign_walking["manifest"]
    foreign_manifest_raw["campaignDigest"] = "9" * 64
    foreign_manifest = type(outcome.plan.manifest).model_validate(foreign_manifest_raw)
    foreign_coordinates = _manifest_coordinates(foreign_manifest)
    foreign_walking["manifest"] = foreign_manifest.model_dump(mode="json", by_alias=True)
    foreign_walking["manifestDigest"] = foreign_manifest.digest()
    foreign_walking["coordinates"] = [
        coordinate.model_dump(mode="json", by_alias=True) for coordinate in foreign_coordinates
    ]
    foreign_candidate = foreign_coordinates[-1]
    foreign_walking["candidateSchedules"][0]["coordinate"] = foreign_candidate.model_dump(
        mode="json", by_alias=True
    )
    foreign_walking["coordinateSetDigest"] = _coordinate_set_digest(
        foreign_manifest,
        foreign_coordinates,
    )
    foreign_walking["planId"] = ""
    foreign_walking["planDigest"] = ""
    with pytest.raises(ValidationError):
        SupervisorBenchmarkCampaignPlan.model_validate(foreign_walking)

    (outcome.run_path / outcome.artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        load_supervisor_benchmark_campaign_plan(campaign, outcome, baseline, sources)


def test_supervisor_benchmark_plan_rejects_foreign_schedule_and_mutated_source(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, baseline, sources, _, _, _ = _sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    outcome = SupervisorBenchmarkCampaignPlanner(output_root=tmp_path / "plans").run(
        campaign,
        baseline,
        sources,
    )
    forged_publication = replace(sources[0].publication, root_digest="9" * 64)
    forged_sources = (
        SupervisorBenchmarkScheduleSource(
            publication=forged_publication,
            authorities=sources[0].authorities,
        ),
    )
    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        load_supervisor_benchmark_campaign_plan(
            campaign,
            outcome,
            baseline,
            forged_sources,
        )

    (baseline.run_path / baseline.artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(SupervisorBenchmarkCampaignPlanError):
        load_supervisor_benchmark_campaign_plan(campaign, outcome, baseline, sources)
