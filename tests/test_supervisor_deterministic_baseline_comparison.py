from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.benchmark.shadow_measurement import WalkingShadowMeasuredBenchmarkRunner
from pajin.domain.models import CampaignManifest
from pajin.runtime.store import RunStore, load_verified_run_events, verify_run_integrity
from pajin.supervision.baseline_comparison import (
    SupervisorDeterministicBaselineLineageAuthority,
    SupervisorDeterministicBaselineLineageError,
    SupervisorDeterministicBaselineLineageRunner,
    load_supervisor_deterministic_baseline_lineage_authority,
)
from pajin.supervision.checkpoint_scheduler import SupervisorCheckpointScheduler
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
from tests.test_walking_mcp_authorization import (
    _walking_shadow_measured_sources,
)


def _comparison_sources(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
):
    campaign = _supervisor_campaign(_walking_campaign(sample_campaign))
    graph_store, _, _, collaboration = _graph(campaign)
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
    invoker, journal, authorities, _, _, _ = _invocation_environment(
        tmp_path,
        campaign,
        provider,
        policy,
        snapshot_input,
        binding,
        configuration,
        collaboration,
        graph_store,
    )
    completion = asyncio.run(invoker.invoke(schedule, authorities))

    structural, measured = _walking_shadow_measured_sources(
        tmp_path / "walking",
        campaign,
        monkeypatch,
    )
    measured_policy = WalkingShadowMeasuredBenchmarkRunner(
        output_root=tmp_path / "measured-policy"
    ).run(campaign, structural, measured)
    return campaign, schedule, journal, authorities, completion, measured_policy


def _republish_authority_run(
    output_root: Path,
    campaign: CampaignManifest,
    *,
    artifact_path: str,
    artifact_payload: object,
    created_event_type: str,
    created_event_payload: dict[str, object],
    start_payload: dict[str, object],
    completed_payload: dict[str, object],
    run_record: dict[str, object],
    extra_artifact: bool = False,
    extra_event: bool = False,
    duplicate_run_keys: bool = False,
) -> tuple[str, Path]:
    store = RunStore.create(output_root, campaign.metadata.name)
    store.append_event("campaign.started", start_payload)
    store.write_json(
        "campaign.json",
        campaign.model_dump(mode="json", by_alias=True),
    )
    store.write_json(artifact_path, artifact_payload)
    if extra_artifact:
        store.write_json("foreign.json", {"authority": "none"})
    store.append_event(created_event_type, created_event_payload)
    if extra_event:
        store.append_event("benchmark.activation.authorized", {"authorized": True})
    bound_run_record = {**run_record, "runId": store.run_id}
    if duplicate_run_keys:
        raw = json.dumps(bound_run_record, separators=(",", ":"))
        raw = raw.replace(
            '"status":"completed"',
            '"status":"running","status":"completed"',
            1,
        )
        store.write_text("run.json", raw)
    else:
        store.write_json("run.json", bound_run_record)
    store.append_event("campaign.completed", completed_payload)
    store.seal()
    return store.run_id, store.path


def test_supervisor_baseline_lineage_binds_sources_without_model_attribution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, schedule, journal, authorities, completion, measured = _comparison_sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    runner = SupervisorDeterministicBaselineLineageRunner(output_root=tmp_path / "lineage")

    first = runner.run(
        campaign,
        completion,
        measured,
        journal=journal,
        schedule_publication=schedule,
        invocation_authorities=authorities,
    )
    second = runner.run(
        campaign,
        completion,
        measured,
        journal=journal,
        schedule_publication=schedule,
        invocation_authorities=authorities,
    )
    authority = first.authority

    assert first.run_id != second.run_id
    assert first.authority == second.authority
    assert authority.comparison_state == "structural-source-bound-not-model-measured"
    assert authority.same_policy_lineage_verified is True
    assert authority.policy_benchmark_comparison_available is True
    assert authority.model_proposal_measurement_attributed is False
    assert authority.benchmark_coordinate_bound_to_invocation is False
    assert authority.model_backed_benchmark_eligible is False
    assert authority.threshold_evaluation_eligible is False
    assert authority.supervisor_activation_eligible is False
    assert authority.execution_authorized is False
    assert authority.measurement.candidate_observed_model_calls == 0
    assert authority.invocation.proposal_digest == completion.proposal.proposal_digest
    assert authority.measurement.comparison_digest == (
        measured.authority.measured_source.comparison_digest
    )
    assert [event.event_type for event in load_verified_run_events(first.run_path)] == [
        "campaign.started",
        "benchmark.supervisor-baseline-lineage.created",
        "campaign.completed",
    ]
    assert verify_run_integrity(first.run_path).valid
    assert (
        load_supervisor_deterministic_baseline_lineage_authority(
            campaign,
            first,
            completion,
            measured,
            journal=journal,
            schedule_publication=schedule,
            invocation_authorities=authorities,
        )
        == authority
    )

    serialized = json.dumps(authority.model_dump(mode="json", by_alias=True))
    assert TARGET_PROMPT not in serialized
    assert "Review the deterministic graph transition without changing scope." not in serialized
    assert "supervisor-provider-secret" not in serialized
    assert "metricDeltas" not in serialized
    assert "baselineValue" not in serialized
    assert "candidateValue" not in serialized


def test_supervisor_baseline_lineage_rejects_authority_escalation_and_coercion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, schedule, journal, authorities, completion, measured = _comparison_sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    outcome = SupervisorDeterministicBaselineLineageRunner(
        output_root=tmp_path / "lineage"
    ).run(
        campaign,
        completion,
        measured,
        journal=journal,
        schedule_publication=schedule,
        invocation_authorities=authorities,
    )
    mutations: tuple[tuple[str, object], ...] = (
        ("modelProposalMeasurementAttributed", True),
        ("benchmarkCoordinateBoundToInvocation", True),
        ("modelBackedBenchmarkEligible", True),
        ("thresholdEvaluationEligible", True),
        ("supervisorActivationEligible", True),
        ("executionAuthorized", True),
        ("samePolicyLineageVerified", 1),
        ("policyBenchmarkComparisonAvailable", 1),
    )
    for field, value in mutations:
        raw = outcome.authority.model_dump(mode="json", by_alias=True)
        raw[field] = value
        with pytest.raises(ValidationError):
            SupervisorDeterministicBaselineLineageAuthority.model_validate(raw)


def test_supervisor_baseline_lineage_rejects_source_identity_and_count_forgery(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, schedule, journal, authorities, completion, measured = _comparison_sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    outcome = SupervisorDeterministicBaselineLineageRunner(
        output_root=tmp_path / "lineage"
    ).run(
        campaign,
        completion,
        measured,
        journal=journal,
        schedule_publication=schedule,
        invocation_authorities=authorities,
    )
    mutations: tuple[tuple[tuple[str, str], object], ...] = (
        (("invocation", "proposalDigest"), "9" * 64),
        (("measurement", "candidatePolicyDigest"), "9" * 64),
        (("measurement", "candidateCoordinateCount"), True),
        (("measurement", "candidateObservedModelCalls"), "0"),
    )
    for path, value in mutations:
        raw = outcome.authority.model_dump(mode="json", by_alias=True)
        raw[path[0]][path[1]] = value
        with pytest.raises(ValidationError):
            SupervisorDeterministicBaselineLineageAuthority.model_validate(raw)


def test_supervisor_baseline_lineage_reverifies_completion_and_sealed_sources(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, schedule, journal, authorities, completion, measured = _comparison_sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    runner = SupervisorDeterministicBaselineLineageRunner(output_root=tmp_path / "lineage")
    outcome = runner.run(
        campaign,
        completion,
        measured,
        journal=journal,
        schedule_publication=schedule,
        invocation_authorities=authorities,
    )
    forged_proposal = completion.proposal.model_copy(update={"proposal_digest": "9" * 64})

    with pytest.raises(SupervisorDeterministicBaselineLineageError):
        runner.run(
            campaign,
            replace(completion, proposal=forged_proposal),
            measured,
            journal=journal,
            schedule_publication=schedule,
            invocation_authorities=authorities,
        )

    (measured.run_path / measured.artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(SupervisorDeterministicBaselineLineageError):
        runner.run(
            campaign,
            completion,
            measured,
            journal=journal,
            schedule_publication=schedule,
            invocation_authorities=authorities,
        )

    (outcome.run_path / outcome.artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(SupervisorDeterministicBaselineLineageError):
        load_supervisor_deterministic_baseline_lineage_authority(
            campaign,
            outcome,
            completion,
            measured,
            journal=journal,
            schedule_publication=schedule,
            invocation_authorities=authorities,
        )


def test_supervisor_baseline_lineage_rejects_resealed_benchmark_envelope_forgery(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, schedule, journal, authorities, completion, measured = _comparison_sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    source_events = load_verified_run_events(measured.run_path)
    start_payload = {
        "campaign": campaign.metadata.name,
        "mode": campaign.spec.mode.value,
        "purpose": "walking-shadow-measured-benchmark",
    }
    completed_payload = {
        "purpose": "walking-shadow-measured-benchmark",
        "artifact": measured.artifact_path,
    }
    run_record = {
        "status": "completed",
        "stage": "walking-shadow-measured-benchmark-sealed",
        "authorityId": measured.authority.authority_id,
        "measurementState": measured.authority.measurement_state,
    }
    cases = (
        {"extra_artifact": True},
        {"extra_event": True},
        {"start_payload": {**start_payload, "purpose": "foreign"}},
        {"completed_payload": {**completed_payload, "artifact": "foreign.json"}},
        {"run_record": {**run_record, "status": "running", "stage": "foreign"}},
        {"duplicate_run_keys": True},
    )
    runner = SupervisorDeterministicBaselineLineageRunner(
        output_root=tmp_path / "lineage"
    )

    for index, mutation in enumerate(cases):
        run_id, run_path = _republish_authority_run(
            tmp_path / f"forged-benchmark-{index}",
            campaign,
            artifact_path=measured.artifact_path,
            artifact_payload=measured.authority.model_dump(mode="json", by_alias=True),
            created_event_type="benchmark.walking-shadow-measured.created",
            created_event_payload=source_events[1].payload,
            start_payload=mutation.get("start_payload", start_payload),
            completed_payload=mutation.get("completed_payload", completed_payload),
            run_record=mutation.get("run_record", run_record),
            extra_artifact=bool(mutation.get("extra_artifact", False)),
            extra_event=bool(mutation.get("extra_event", False)),
            duplicate_run_keys=bool(mutation.get("duplicate_run_keys", False)),
        )
        forged = replace(measured, run_id=run_id, run_path=run_path)
        with pytest.raises(SupervisorDeterministicBaselineLineageError):
            runner.run(
                campaign,
                completion,
                forged,
                journal=journal,
                schedule_publication=schedule,
                invocation_authorities=authorities,
            )


def test_supervisor_baseline_lineage_reader_rejects_resealed_output_envelope_forgery(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, schedule, journal, authorities, completion, measured = _comparison_sources(
        tmp_path,
        sample_campaign,
        monkeypatch,
    )
    outcome = SupervisorDeterministicBaselineLineageRunner(
        output_root=tmp_path / "lineage"
    ).run(
        campaign,
        completion,
        measured,
        journal=journal,
        schedule_publication=schedule,
        invocation_authorities=authorities,
    )
    source_events = load_verified_run_events(outcome.run_path)
    start_payload = {
        "campaign": campaign.metadata.name,
        "mode": campaign.spec.mode.value,
        "purpose": "supervisor-deterministic-baseline-lineage",
    }
    completed_payload = {
        "purpose": "supervisor-deterministic-baseline-lineage",
        "artifact": outcome.artifact_path,
    }
    run_record = {
        "status": "completed",
        "stage": "supervisor-deterministic-baseline-lineage-sealed",
        "authorityId": outcome.authority.authority_id,
        "comparisonState": outcome.authority.comparison_state,
    }
    cases = (
        {"extra_artifact": True},
        {"extra_event": True},
        {"start_payload": {**start_payload, "purpose": "foreign"}},
        {"completed_payload": {**completed_payload, "artifact": "foreign.json"}},
        {"run_record": {**run_record, "status": "running", "stage": "foreign"}},
        {"duplicate_run_keys": True},
    )

    for index, mutation in enumerate(cases):
        run_id, run_path = _republish_authority_run(
            tmp_path / f"forged-lineage-{index}",
            campaign,
            artifact_path=outcome.artifact_path,
            artifact_payload=outcome.authority.model_dump(mode="json", by_alias=True),
            created_event_type="benchmark.supervisor-baseline-lineage.created",
            created_event_payload=source_events[1].payload,
            start_payload=mutation.get("start_payload", start_payload),
            completed_payload=mutation.get("completed_payload", completed_payload),
            run_record=mutation.get("run_record", run_record),
            extra_artifact=bool(mutation.get("extra_artifact", False)),
            extra_event=bool(mutation.get("extra_event", False)),
            duplicate_run_keys=bool(mutation.get("duplicate_run_keys", False)),
        )
        forged = replace(outcome, run_id=run_id, run_path=run_path)
        with pytest.raises(SupervisorDeterministicBaselineLineageError):
            load_supervisor_deterministic_baseline_lineage_authority(
                campaign,
                forged,
                completion,
                measured,
                journal=journal,
                schedule_publication=schedule,
                invocation_authorities=authorities,
            )
