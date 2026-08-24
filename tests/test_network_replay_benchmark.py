from __future__ import annotations

from base64 import b64decode
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_network_service_admission import _Context, _context
from test_network_service_identification import _worker_entry

from pajin.domain.models import CampaignManifest
from pajin.workflow.network_replay_benchmark import (
    NetworkBenchmarkGroundTruthClass,
    NetworkProtocolLabelComparison,
    NetworkServiceBenchmarkFixtureProfile,
    NetworkServiceReplayBenchmarkError,
    NetworkServiceReplayValidation,
    bind_network_service_fresh_worker_replay,
    registered_network_service_benchmark_fixture_profile,
)
from pajin.workflow.network_service_admission import (
    NetworkProtocolKnowledgeAdmission,
    NetworkProtocolKnowledgeAdmissionGate,
)


async def _admitted_source(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    run_id: str,
    request_id: str,
    banner: bytes,
    service_name: str | None,
) -> tuple[_Context, NetworkProtocolKnowledgeAdmission]:
    context = await _context(
        tmp_path,
        sample_campaign,
        run_id=run_id,
        request_id=request_id,
        banner=banner,
        service_name=service_name,
    )
    gate = NetworkProtocolKnowledgeAdmissionGate(
        graph_store=context.graph_store,
        graph_admission=context.graph_admission,
        trusted_lineages=context.graph_lineages,
    )
    candidate = gate.prepare_candidate(context.source_inputs, context.graph_binding)
    return context, gate.admit(context.source_inputs, candidate)


async def _sealed_replay(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    run_id: str,
    request_id: str,
    banner: bytes,
    service_name: str | None,
) -> _Context:
    return await _context(
        tmp_path,
        sample_campaign,
        run_id=run_id,
        request_id=request_id,
        banner=banner,
        service_name=service_name,
    )


@pytest.mark.asyncio
async def test_fresh_worker_replay_binds_matching_label_without_confirmation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "source",
        sample_campaign,
        run_id="run_20260824T130000Z_a1b2c3d4",
        request_id="tool_network_service_source",
        banner=b"SSH-2.0-PAJIN-Source\r\n",
        service_name="ssh",
    )
    replay = await _sealed_replay(
        tmp_path / "replay",
        sample_campaign,
        run_id="run_20260824T130100Z_b1c2d3e4",
        request_id="tool_network_service_replay",
        banner=b"SSH-2.0-PAJIN-Replay\r\n",
        service_name="ssh",
    )

    validation = bind_network_service_fresh_worker_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
    )

    assert validation.label_comparison is NetworkProtocolLabelComparison.MATCHED
    assert validation.state == "fresh-worker-replay-protocol-label-match"
    assert validation.banner_digest_matched is False
    assert validation.source_execution.worker_execution_id != (
        validation.replay_execution.worker_execution_id
    )
    assert validation.source_execution.action_permit.permit_id != (
        validation.replay_execution.action_permit.permit_id
    )
    assert validation.service_observation_confirmed is False
    assert validation.profile_validation_floor_satisfied is False
    assert validation.finding_authority is False
    assert validation.execution_authorized is False
    assert (
        NetworkServiceReplayValidation.model_validate(
            validation.model_dump(mode="json", by_alias=True)
        )
        == validation
    )


def test_isolated_fixture_profile_registers_five_labels_and_negative_control() -> None:
    profile = registered_network_service_benchmark_fixture_profile()
    worker = _worker_entry()

    assert profile.state == "registered-fixture-ground-truth-not-measured"
    assert [case.fixture_id for case in profile.cases] == sorted(
        case.fixture_id for case in profile.cases
    )
    assert {case.expected_service_name for case in profile.cases} == {
        None,
        "ftp",
        "imap",
        "pop3",
        "smtp",
        "ssh",
    }
    negative = tuple(
        case
        for case in profile.cases
        if case.ground_truth_class is NetworkBenchmarkGroundTruthClass.NEGATIVE_CONTROL
    )
    assert len(negative) == 1
    assert negative[0].expected_service_name is None
    for case in profile.cases:
        banner = b64decode(case.banner_base64, validate=True)
        assert worker._network_service_name(banner) == case.expected_service_name
    assert profile.target_profile_selected is False
    assert profile.fixture_execution_authorized is False
    assert profile.replay_evidence_bound is False
    assert profile.benchmark_measurement_observed is False
    assert profile.profile_validation_floor_satisfied is False
    assert (
        NetworkServiceBenchmarkFixtureProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        == profile
    )

    mutated = profile.model_dump(mode="json", by_alias=True)
    mutated["profileId"] = ""
    mutated["profileDigest"] = ""
    mutated["cases"][0]["expectedServiceName"] = "ssh"
    with pytest.raises(ValidationError, match="code authority"):
        NetworkServiceBenchmarkFixtureProfile.model_validate(mutated)


@pytest.mark.asyncio
async def test_unknown_replay_remains_unresolved_not_negative(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "unknown-source",
        sample_campaign,
        run_id="run_20260824T131000Z_c1d2e3f4",
        request_id="tool_network_unknown_source",
        banner=b"PAJIN unknown source banner\r\n",
        service_name=None,
    )
    replay = await _sealed_replay(
        tmp_path / "unknown-replay",
        sample_campaign,
        run_id="run_20260824T131100Z_d1e2f3a4",
        request_id="tool_network_unknown_replay",
        banner=b"PAJIN different unknown banner\r\n",
        service_name=None,
    )

    validation = bind_network_service_fresh_worker_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
    )

    assert admission.bounded_hypothesis_admitted is False
    assert validation.label_comparison is NetworkProtocolLabelComparison.UNRESOLVED
    assert validation.state == "fresh-worker-replay-protocol-label-unresolved"
    assert validation.negative_control_observed is False
    assert validation.service_observation_confirmed is False
    assert validation.ground_truth_case_bound is False


@pytest.mark.asyncio
async def test_replay_reports_label_change_and_rejects_authority_reuse(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "changed-source",
        sample_campaign,
        run_id="run_20260824T132000Z_e1f2a3b4",
        request_id="tool_network_changed_source",
        banner=b"SSH-2.0-PAJIN-Source\r\n",
        service_name="ssh",
    )
    replay = await _sealed_replay(
        tmp_path / "changed-replay",
        sample_campaign,
        run_id="run_20260824T132100Z_f1a2b3c4",
        request_id="tool_network_changed_replay",
        banner=b"220 PAJIN ESMTP service ready\r\n",
        service_name="smtp",
    )

    validation = bind_network_service_fresh_worker_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
    )
    assert validation.label_comparison is NetworkProtocolLabelComparison.CHANGED
    assert validation.state == "fresh-worker-replay-protocol-label-changed"
    assert validation.service_observation_confirmed is False

    escalated = validation.model_dump(mode="json", by_alias=True)
    escalated["validationId"] = ""
    escalated["validationDigest"] = ""
    escalated["serviceObservationConfirmed"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        NetworkServiceReplayValidation.model_validate(escalated)

    with pytest.raises(NetworkServiceReplayBenchmarkError, match="failed closed"):
        bind_network_service_fresh_worker_replay(
            source.source_inputs,
            admission,
            source.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=source.graph_store,
        )
