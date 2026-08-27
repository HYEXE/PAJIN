from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_system_inspection_admission import _Context, _context

from pajin.discovery import SystemSurfaceClass
from pajin.domain.models import CampaignManifest
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow.system_inspection_admission import (
    SystemInspectionExecutionTrustAnchor,
    SystemInspectionKnowledgeAdmission,
    SystemInspectionReviewSignal,
    SystemInspectionSourceKind,
    system_inspection_execution_public_key,
)
from pajin.workflow.system_replay_benchmark import (
    SystemBenchmarkExpectedOutcome,
    SystemBenchmarkGroundTruthClass,
    SystemInspectionBenchmarkFixtureProfile,
    SystemInspectionReplayBenchmarkError,
    SystemInspectionReplayComparison,
    SystemInspectionReplayMode,
    SystemInspectionReplayValidation,
    _require_stored_source_admission,
    bind_system_inspection_replay,
    load_verified_system_inspection_replay_validation,
    registered_system_inspection_benchmark_fixture_profile,
)

SNAPSHOT_DIGEST = sha256(b"system-immutable-snapshot:test-v1").hexdigest()


async def _admitted_source(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: SystemSurfaceClass,
    source_kind: SystemInspectionSourceKind,
    snapshot_digest: str | None,
    result_body: bytes,
    review_signal: SystemInspectionReviewSignal | None | object = ...,
    run_id: str,
    request_id: str,
    execution_id: str,
    result_size: int = 4_096,
) -> tuple[_Context, SystemInspectionKnowledgeAdmission]:
    context = await _context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        source_kind=source_kind,
        immutable_snapshot_sha256=snapshot_digest,
        result_body=result_body,
        result_size=result_size,
        review_signal=review_signal,
        run_id=run_id,
        request_id=request_id,
        execution_id=execution_id,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    return context, context.gate.admit(context.source_inputs, candidate)


async def _sealed_replay(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: SystemSurfaceClass,
    source_kind: SystemInspectionSourceKind,
    snapshot_digest: str | None,
    result_body: bytes,
    review_signal: SystemInspectionReviewSignal | None | object = ...,
    run_id: str,
    request_id: str,
    execution_id: str,
    result_size: int = 4_096,
    execution_time_offset: timedelta = timedelta(seconds=10),
) -> _Context:
    return await _context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        source_kind=source_kind,
        immutable_snapshot_sha256=snapshot_digest,
        result_body=result_body,
        result_size=result_size,
        review_signal=review_signal,
        run_id=run_id,
        request_id=request_id,
        execution_id=execution_id,
        execution_time_offset=execution_time_offset,
    )


@pytest.mark.asyncio
async def test_same_immutable_snapshot_reanalysis_projects_only_neutral_match(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "snapshot-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"sanitized-snapshot-metadata-v1",
        run_id="run_20260825T140000Z_systemsnap1",
        request_id="tool_system_snapshot_source",
        execution_id="system-execution:snapshot-source",
    )
    replay = await _sealed_replay(
        tmp_path / "snapshot-replay",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"sanitized-snapshot-metadata-v1",
        run_id="run_20260825T140100Z_systemsnap2",
        request_id="tool_system_snapshot_replay",
        execution_id="system-execution:snapshot-replay",
    )

    validation = bind_system_inspection_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.replay_mode is SystemInspectionReplayMode.IMMUTABLE_SNAPSHOT_REANALYSIS
    assert validation.comparison is SystemInspectionReplayComparison.MATCHED
    assert validation.state == "immutable-snapshot-reanalysis-match"
    assert validation.result_body_digest_matched is True
    assert validation.result_bytes_matched is True
    assert validation.review_signal_matched is True
    assert validation.domain_validation_strategy_satisfied is True
    assert validation.deployment_context_reverification_required is True
    assert validation.self_authenticating_projection is False
    assert validation.causal_replay_order_verified is True
    assert validation.source_execution.result_receipt.immutable_snapshot_sha256 == (SNAPSHOT_DIGEST)
    assert validation.source_execution.action_permit.permit_id != (
        validation.replay_execution.action_permit.permit_id
    )
    assert validation.host_state_confirmed is False
    assert validation.ground_truth_case_bound is False
    assert validation.replay_authorized is False
    assert validation.execution_authorized is False
    assert (
        SystemInspectionReplayValidation.model_validate(
            validation.model_dump(mode="json", by_alias=True)
        )
        == validation
    )

    tampered = validation.model_dump(mode="json", by_alias=True)
    tampered["validationId"] = ""
    tampered["validationDigest"] = ""
    tampered["replayExecution"]["sourceRootDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="execution projection"):
        SystemInspectionReplayValidation.model_validate(tampered)

    bytes_mutated = deepcopy(validation.model_dump(mode="json", by_alias=True))
    bytes_mutated["validationId"] = ""
    bytes_mutated["validationDigest"] = ""
    bytes_mutated["resultBytesMatched"] = False
    with pytest.raises(ValidationError, match="neutral Replay comparison"):
        SystemInspectionReplayValidation.model_validate(bytes_mutated)

    coerced = deepcopy(validation.model_dump(mode="json", by_alias=True))
    coerced["validationId"] = ""
    coerced["validationDigest"] = ""
    coerced["resultBytesMatched"] = 1
    with pytest.raises(ValidationError, match="comparison markers"):
        SystemInspectionReplayValidation.model_validate(coerced)


@pytest.mark.asyncio
async def test_same_digest_with_different_signed_result_size_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "bytes-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"same-digest-different-signed-size",
        result_size=4_096,
        run_id="run_20260825T140200Z_systembytes1",
        request_id="tool_system_bytes_source",
        execution_id="system-execution:bytes-source",
    )
    replay = await _sealed_replay(
        tmp_path / "bytes-replay",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"same-digest-different-signed-size",
        result_size=4_097,
        run_id="run_20260825T140300Z_systembytes2",
        request_id="tool_system_bytes_replay",
        execution_id="system-execution:bytes-replay",
    )

    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        bind_system_inspection_replay(
            source.source_inputs,
            admission,
            replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_fresh_authenticated_digest_change_without_signal_remains_unresolved(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "fresh-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.HOST,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-host-metadata-source",
        run_id="run_20260825T141000Z_systemlive1",
        request_id="tool_system_live_source",
        execution_id="system-execution:live-source",
    )
    replay = await _sealed_replay(
        tmp_path / "fresh-replay",
        sample_campaign,
        surface_class=SystemSurfaceClass.HOST,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-host-metadata-replay",
        run_id="run_20260825T141100Z_systemlive2",
        request_id="tool_system_live_replay",
        execution_id="system-execution:live-replay",
    )

    validation = bind_system_inspection_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.replay_mode is SystemInspectionReplayMode.FRESH_AUTHENTICATED_INSPECTION
    assert validation.comparison is SystemInspectionReplayComparison.UNRESOLVED
    assert validation.state == "fresh-authenticated-inspection-unresolved"
    assert validation.result_body_digest_matched is False
    assert validation.review_signal_matched is True
    assert validation.domain_validation_strategy_satisfied is False
    assert validation.host_state_confirmed is False
    assert validation.negative_control_observed is False
    assert admission.bounded_hypothesis_admitted is False

    overstated = validation.model_dump(mode="json", by_alias=True)
    overstated["validationId"] = ""
    overstated["validationDigest"] = ""
    overstated["domainValidationStrategySatisfied"] = True
    with pytest.raises(ValidationError, match="neutral Replay comparison"):
        SystemInspectionReplayValidation.model_validate(overstated)


@pytest.mark.asyncio
async def test_fresh_authenticated_review_signal_change_is_neutral_and_non_authorizing(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "changed-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-configuration-source",
        run_id="run_20260825T142000Z_systemchange1",
        request_id="tool_system_changed_source",
        execution_id="system-execution:changed-source",
    )
    replay = await _sealed_replay(
        tmp_path / "changed-replay",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-configuration-replay",
        review_signal=None,
        run_id="run_20260825T142100Z_systemchange2",
        request_id="tool_system_changed_replay",
        execution_id="system-execution:changed-replay",
    )

    validation = bind_system_inspection_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is SystemInspectionReplayComparison.CHANGED
    assert validation.state == "fresh-authenticated-inspection-changed"
    assert validation.review_signal_matched is False
    assert validation.configuration_state_confirmed is False
    assert validation.finding_authority is False

    escalated = validation.model_dump(mode="json", by_alias=True)
    escalated["validationId"] = ""
    escalated["validationDigest"] = ""
    escalated["hostStateConfirmed"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        SystemInspectionReplayValidation.model_validate(escalated)


@pytest.mark.asyncio
async def test_replay_rejects_authority_reuse_or_incomparable_source_provenance(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "reuse-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.SERVICE,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"sanitized-service-source",
        run_id="run_20260825T143000Z_systemreuse1",
        request_id="tool_system_reuse_source",
        execution_id="system-execution:reuse-source",
    )

    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        bind_system_inspection_replay(
            source.source_inputs,
            admission,
            source.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=source.graph_store,
            trust_anchor=source.trust_anchor,
        )

    live_replay = await _sealed_replay(
        tmp_path / "mixed-live-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.SERVICE,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-service-source",
        run_id="run_20260825T143200Z_systemreuse3",
        request_id="tool_system_mixed_live",
        execution_id="system-execution:mixed-live",
    )
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        bind_system_inspection_replay(
            source.source_inputs,
            admission,
            live_replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=live_replay.graph_store,
            trust_anchor=source.trust_anchor,
        )

    different_snapshot_replay = await _sealed_replay(
        tmp_path / "different-snapshot",
        sample_campaign,
        surface_class=SystemSurfaceClass.SERVICE,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=sha256(b"different-system-snapshot").hexdigest(),
        result_body=b"sanitized-service-source",
        run_id="run_20260825T143100Z_systemreuse2",
        request_id="tool_system_different_snapshot",
        execution_id="system-execution:different-snapshot",
    )
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        bind_system_inspection_replay(
            source.source_inputs,
            admission,
            different_snapshot_replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=different_snapshot_replay.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_replay_execution_must_start_after_source_completion(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "causal-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.PROCESS,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-process-source",
        run_id="run_20260825T143300Z_systemcausal1",
        request_id="tool_system_causal_source",
        execution_id="system-execution:causal-source",
    )
    noncausal_replay = await _sealed_replay(
        tmp_path / "noncausal-replay",
        sample_campaign,
        surface_class=SystemSurfaceClass.PROCESS,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-process-replay",
        run_id="run_20260825T143400Z_systemcausal2",
        request_id="tool_system_noncausal_replay",
        execution_id="system-execution:noncausal-replay",
        execution_time_offset=timedelta(0),
    )

    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        bind_system_inspection_replay(
            source.source_inputs,
            admission,
            noncausal_replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=noncausal_replay.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_source_admission_must_be_stored_in_the_exact_graph_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "stored-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.HOST,
        source_kind=SystemInspectionSourceKind.LIVE_AUTHENTICATED_HOST,
        snapshot_digest=None,
        result_body=b"sanitized-stored-source",
        run_id="run_20260825T144000Z_systemstored1",
        request_id="tool_system_stored_source",
        execution_id="system-execution:stored-source",
    )
    _require_stored_source_admission(admission, source.graph_store)

    foreign_store = SQLiteGraphStore(
        tmp_path / "foreign-graph.sqlite3",
        campaign_id=admission.candidate.graph.snapshot.campaign_id,
    )
    with pytest.raises(ValueError, match="not stored exactly"):
        _require_stored_source_admission(admission, foreign_store)


@pytest.mark.asyncio
async def test_contextful_wire_loader_rechecks_graph_evidence_and_external_trust_anchor(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission = await _admitted_source(
        tmp_path / "wire-source",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"sanitized-wire-source",
        run_id="run_20260825T145000Z_systemwire1",
        request_id="tool_system_wire_source",
        execution_id="system-execution:wire-source",
    )
    replay = await _sealed_replay(
        tmp_path / "wire-replay",
        sample_campaign,
        surface_class=SystemSurfaceClass.CONFIGURATION,
        source_kind=SystemInspectionSourceKind.IMMUTABLE_HOST_SNAPSHOT,
        snapshot_digest=SNAPSHOT_DIGEST,
        result_body=b"sanitized-wire-source",
        run_id="run_20260825T145100Z_systemwire2",
        request_id="tool_system_wire_replay",
        execution_id="system-execution:wire-replay",
    )
    validation = bind_system_inspection_replay(
        source.source_inputs,
        admission,
        replay.source_inputs,
        source_graph_store=source.graph_store,
        replay_graph_store=replay.graph_store,
        trust_anchor=source.trust_anchor,
    )
    wire = validation.model_dump(mode="json", by_alias=True)

    assert (
        load_verified_system_inspection_replay_validation(
            wire,
            source.source_inputs,
            replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=source.trust_anchor,
        )
        == validation
    )

    coerced_verification = deepcopy(wire)
    coerced_verification["sourceExecution"]["verification"]["valid"] = 1
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        load_verified_system_inspection_replay_validation(
            coerced_verification,
            source.source_inputs,
            replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=source.trust_anchor,
        )

    empty_store = SQLiteGraphStore(
        tmp_path / "wire-empty-source-graph.sqlite3",
        campaign_id=admission.candidate.graph.snapshot.campaign_id,
    )
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        load_verified_system_inspection_replay_validation(
            wire,
            source.source_inputs,
            replay.source_inputs,
            source_graph_store=empty_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=source.trust_anchor,
        )

    forged_graph = deepcopy(wire)
    forged_graph["validationId"] = ""
    forged_graph["validationDigest"] = ""
    forged_graph["sourceAdmission"]["admissionId"] = ""
    forged_graph["sourceAdmission"]["admissionDigest"] = ""
    forged_event = forged_graph["sourceAdmission"]["observationGraphEvent"]
    forged_event["eventId"] = ""
    forged_event["eventDigest"] = ""
    forged_event["occurredAt"] = "2026-08-25T14:59:59Z"
    canonical_forged_event = type(admission.observation_graph_event).model_validate(forged_event)
    forged_hypothesis_event = forged_graph["sourceAdmission"]["hypothesisGraphEvent"]
    assert forged_hypothesis_event is not None
    forged_hypothesis_event["eventId"] = ""
    forged_hypothesis_event["eventDigest"] = ""
    forged_hypothesis_event["previousEventDigest"] = canonical_forged_event.event_digest
    forged_graph_model = SystemInspectionReplayValidation.model_validate(forged_graph)
    assert forged_graph_model.stored_source_admission_verified is True
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        load_verified_system_inspection_replay_validation(
            forged_graph_model,
            source.source_inputs,
            replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=source.trust_anchor,
        )

    forged_source_snapshot = deepcopy(wire)
    forged_source_snapshot["validationId"] = ""
    forged_source_snapshot["validationDigest"] = ""
    forged_admission = forged_source_snapshot["sourceAdmission"]
    forged_admission["admissionId"] = ""
    forged_admission["admissionDigest"] = ""
    forged_candidate = forged_admission["candidate"]
    forged_candidate["candidateId"] = ""
    forged_candidate["candidateDigest"] = ""
    forged_candidate["sourceExecutionSnapshot"]["snapshotDigest"] = "f" * 64
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        load_verified_system_inspection_replay_validation(
            forged_source_snapshot,
            source.source_inputs,
            replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=source.trust_anchor,
        )

    foreign_anchor_payload = source.trust_anchor.model_dump(mode="json", by_alias=True)
    foreign_anchor_payload["keys"][0]["publicKeyBase64url"] = (
        system_inspection_execution_public_key(
            sha256(b"SYS-001D foreign deployment trust anchor").digest()
        )
    )
    foreign_anchor = SystemInspectionExecutionTrustAnchor.model_validate(foreign_anchor_payload)
    with pytest.raises(SystemInspectionReplayBenchmarkError, match="failed closed"):
        load_verified_system_inspection_replay_validation(
            wire,
            source.source_inputs,
            replay.source_inputs,
            source_graph_store=source.graph_store,
            replay_graph_store=replay.graph_store,
            trust_anchor=foreign_anchor,
        )


def test_disposable_host_fixture_profile_registers_coverage_controls_and_evidence() -> None:
    profile = registered_system_inspection_benchmark_fixture_profile()

    assert profile.state == "registered-fixture-ground-truth-not-measured"
    assert profile.covered_surface_classes == tuple(SystemSurfaceClass)
    assert [case.fixture_id for case in profile.cases] == sorted(
        case.fixture_id for case in profile.cases
    )
    assert {case.surface_class for case in profile.cases} == set(SystemSurfaceClass)
    assert {case.ground_truth_class for case in profile.cases} == {
        SystemBenchmarkGroundTruthClass.KNOWN_POSITIVE,
        SystemBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
        SystemBenchmarkGroundTruthClass.PRIVILEGE_DENIAL_CONTROL,
    }
    denial = tuple(
        case
        for case in profile.cases
        if case.expected_outcome is SystemBenchmarkExpectedOutcome.PRIVILEGE_DENIED
    )
    assert len(denial) == 1
    assert "privilege-denial-receipt" in denial[0].required_evidence
    assert all("cleanup-receipt" in case.required_evidence for case in profile.cases)
    assert profile.private_ground_truth_requirements_registered is True
    assert profile.private_ground_truth_verified is False
    assert profile.disposable_host_required is True
    assert profile.evidence_completeness_required is True
    assert profile.host_agent_provisioned is False
    assert profile.fixture_execution_authorized is False
    assert profile.cleanup_observed is False
    assert profile.benchmark_measurement_observed is False
    assert profile.profile_validation_floor_satisfied is False
    assert profile.root_authority_asserted is False
    assert profile.execution_authorized is False
    assert (
        SystemInspectionBenchmarkFixtureProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        == profile
    )

    mutated = deepcopy(profile.model_dump(mode="json", by_alias=True))
    mutated["profileId"] = ""
    mutated["profileDigest"] = ""
    mutated["cases"][0]["surfaceClass"] = SystemSurfaceClass.HOST.value
    with pytest.raises(ValidationError):
        SystemInspectionBenchmarkFixtureProfile.model_validate(mutated)

    escalated = deepcopy(profile.model_dump(mode="json", by_alias=True))
    escalated["profileId"] = ""
    escalated["profileDigest"] = ""
    escalated["rootAuthorityAsserted"] = 1
    with pytest.raises(ValidationError, match="authority markers"):
        SystemInspectionBenchmarkFixtureProfile.model_validate(escalated)

    coerced_requirement = deepcopy(profile.model_dump(mode="json", by_alias=True))
    coerced_requirement["profileId"] = ""
    coerced_requirement["profileDigest"] = ""
    coerced_requirement["privateGroundTruthRequirementsRegistered"] = 1
    with pytest.raises(ValidationError, match="requirement markers"):
        SystemInspectionBenchmarkFixtureProfile.model_validate(coerced_requirement)

    forged_verification = deepcopy(profile.model_dump(mode="json", by_alias=True))
    forged_verification["profileId"] = ""
    forged_verification["profileDigest"] = ""
    forged_verification["privateGroundTruthVerified"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        SystemInspectionBenchmarkFixtureProfile.model_validate(forged_verification)
