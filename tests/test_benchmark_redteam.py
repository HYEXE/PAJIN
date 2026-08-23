from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.benchmark.redteam import (
    RedteamBenchmarkCapability,
    RedteamBenchmarkError,
    RedteamBenchmarkMetric,
    RedteamBenchmarkMetricObservation,
    RedteamBenchmarkMetricStatus,
    RedteamBenchmarkProfileSet,
    RedteamBenchmarkRunObservation,
    RedteamBenchmarkRunObservationRecorder,
    RedteamBenchmarkSourceKind,
    RedteamDetectionCaseObservation,
    RedteamGroundTruthClass,
    RedteamInitialBenchmarkReport,
    RedteamInitialBenchmarkRunner,
    RedteamMetricApplicability,
    RedteamProfileBenchmarkContract,
    RedteamReplayCaseObservation,
    aggregate_redteam_initial_benchmark,
    load_redteam_initial_benchmark_report,
    registered_redteam_benchmark_profile_set,
)
from pajin.capabilities import (
    CapabilityOracleDecision,
    CapabilityOracleObservation,
    CapabilityReplayObservation,
    CapabilityReplayVerdict,
    ExistingModeCapabilityBundle,
    existing_mode_capability_bundle,
)
from pajin.control_plane.redteam_profiles import (
    REDTEAM_LLM_PROFILE,
    REDTEAM_LLM_RAG_PROFILE,
    REDTEAM_MCP_PROFILE,
    REDTEAM_WEB_PROFILE,
)
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.redteam_product_flow import (
    RedteamProductFlowError,
    RedteamProductFlowProjection,
    RedteamProductFlowProjector,
    load_redteam_product_flow,
)

NOW = datetime(2026, 8, 21, 1, tzinfo=UTC)


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _bundle() -> ExistingModeCapabilityBundle:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
        demo_mcp_tool(),
    ):
        tools.register(tool)
    return existing_mode_capability_bundle(tools, include_registered_mcp=True)


def _contract(
    profile_set: RedteamBenchmarkProfileSet,
    profile_id: str,
    capability_id: str,
) -> tuple[RedteamProfileBenchmarkContract, RedteamBenchmarkCapability]:
    profile = profile_set.profile(profile_id)
    capability = next(
        item
        for item in profile.capabilities
        if item.capability.capability.capability_id == capability_id
    )
    return profile, capability


def _detection_observation(
    profile_set: RedteamBenchmarkProfileSet,
    *,
    profile_id: str,
    capability_id: str,
    label: str,
    ground_truth: RedteamGroundTruthClass,
    detected: bool,
    source_kind: RedteamBenchmarkSourceKind = RedteamBenchmarkSourceKind.PROFILE_EXECUTION,
    extra_case: RedteamDetectionCaseObservation | None = None,
    cost_usd: float = 0.01,
) -> RedteamBenchmarkRunObservation:
    profile, capability = _contract(profile_set, profile_id, capability_id)
    evidence_digest = _digest(f"evidence:{label}")
    case = RedteamDetectionCaseObservation(
        caseId=f"case:{label}",
        groundTruth=ground_truth,
        detected=detected,
        evidenceDigest=evidence_digest,
    )
    cases = tuple(
        sorted(
            (case, *((extra_case,) if extra_case else ())),
            key=lambda item: item.case_id,
        )
    )
    oracle = CapabilityOracleObservation(
        capability=capability.capability,
        benchmarkId=capability.benchmark_id,
        decision=CapabilityOracleDecision.SUCCEEDED,
        observedAt=NOW,
        evidenceDigest=evidence_digest,
    )
    execution = source_kind is RedteamBenchmarkSourceKind.PROFILE_EXECUTION
    return RedteamBenchmarkRunObservation(
        profileSetDigest=profile_set.profile_set_digest,
        profileContractDigest=profile.contract_digest,
        profileId=profile_id,
        capability=capability.capability,
        benchmarkId=capability.benchmark_id,
        benchmarkMappingDigest=capability.benchmark_mapping_digest,
        sourceKind=source_kind,
        sourceRunId=f"source:{label}",
        sourceRootDigest=_digest(f"root:{label}"),
        sourceArtifactPath=f"evidence/{label}.json",
        sourceArtifactSha256=evidence_digest,
        startedAt=NOW,
        completedAt=NOW + timedelta(seconds=2),
        oracleObservation=oracle,
        detectionCases=cases,
        replayCases=(),
        requestUnits=capability.request_unit_cost if execution else 0,
        toolCallCount=1 if execution else 0,
        modelCallCount=(
            capability.request_unit_cost
            if execution and profile_id in {REDTEAM_LLM_PROFILE, REDTEAM_LLM_RAG_PROFILE}
            else 0
        ),
        costUsd=cost_usd if execution else 0,
        evidenceExpectedCount=len(cases),
        evidenceVerifiedCount=len(cases),
    )


def _replay_observation(
    profile_set: RedteamBenchmarkProfileSet,
    *,
    profile_id: str,
    capability_id: str,
    label: str,
    case_id: str,
) -> RedteamBenchmarkRunObservation:
    profile, capability = _contract(profile_set, profile_id, capability_id)
    evidence_digest = _digest(f"replay:{label}")
    replay = CapabilityReplayObservation(
        capability=capability.capability,
        contractId=capability.replay_contract_ids[0],
        verdict=CapabilityReplayVerdict.SUPPORTS,
        observedAt=NOW + timedelta(seconds=3),
        evidenceDigest=evidence_digest,
    )
    return RedteamBenchmarkRunObservation(
        profileSetDigest=profile_set.profile_set_digest,
        profileContractDigest=profile.contract_digest,
        profileId=profile_id,
        capability=capability.capability,
        benchmarkId=capability.benchmark_id,
        benchmarkMappingDigest=capability.benchmark_mapping_digest,
        sourceKind=RedteamBenchmarkSourceKind.INDEPENDENT_REPLAY,
        sourceRunId=f"source:{label}",
        sourceRootDigest=_digest(f"root:{label}"),
        sourceArtifactPath=f"evidence/{label}.json",
        sourceArtifactSha256=evidence_digest,
        startedAt=NOW + timedelta(seconds=2),
        completedAt=NOW + timedelta(seconds=4),
        replayCases=(
            RedteamReplayCaseObservation(
                caseId=case_id,
                expectedVerdict=CapabilityReplayVerdict.SUPPORTS,
                observation=replay,
            ),
        ),
        requestUnits=capability.request_unit_cost,
        toolCallCount=1,
        modelCallCount=capability.request_unit_cost,
        costUsd=0.005,
        evidenceExpectedCount=1,
        evidenceVerifiedCount=1,
    )


def _policy_observation(
    profile_set: RedteamBenchmarkProfileSet,
    *,
    profile_id: str,
    capability_id: str,
) -> RedteamBenchmarkRunObservation:
    profile, capability = _contract(profile_set, profile_id, capability_id)
    label = f"policy-{profile_id}"
    return RedteamBenchmarkRunObservation(
        profileSetDigest=profile_set.profile_set_digest,
        profileContractDigest=profile.contract_digest,
        profileId=profile_id,
        capability=capability.capability,
        benchmarkId=capability.benchmark_id,
        benchmarkMappingDigest=capability.benchmark_mapping_digest,
        sourceKind=RedteamBenchmarkSourceKind.POLICY_DENIAL,
        sourceRunId=f"source:{label}",
        sourceRootDigest=_digest(f"root:{label}"),
        sourceArtifactPath=f"evidence/{label}.json",
        sourceArtifactSha256=_digest(f"evidence:{label}"),
        startedAt=NOW,
        completedAt=NOW + timedelta(seconds=1),
        policyDenialExpected=True,
        policyDenied=True,
        requestUnits=0,
        toolCallCount=0,
        modelCallCount=0,
        costUsd=0,
        evidenceExpectedCount=1,
        evidenceVerifiedCount=1,
    )


def _observations(
    profile_set: RedteamBenchmarkProfileSet,
) -> tuple[RedteamBenchmarkRunObservation, ...]:
    observations: list[RedteamBenchmarkRunObservation] = []
    llm_ids = [
        item.capability.capability.capability_id
        for item in profile_set.profile(REDTEAM_LLM_PROFILE).capabilities
    ]
    for index, capability_id in enumerate(llm_ids):
        observations.extend(
            (
                _detection_observation(
                    profile_set,
                    profile_id=REDTEAM_LLM_PROFILE,
                    capability_id=capability_id,
                    label=f"llm-positive-{index}",
                    ground_truth=RedteamGroundTruthClass.KNOWN_POSITIVE,
                    detected=True,
                ),
                _replay_observation(
                    profile_set,
                    profile_id=REDTEAM_LLM_PROFILE,
                    capability_id=capability_id,
                    label=f"llm-replay-{index}",
                    case_id=f"case:llm-positive-{index}",
                ),
                _detection_observation(
                    profile_set,
                    profile_id=REDTEAM_LLM_PROFILE,
                    capability_id=capability_id,
                    label=f"llm-negative-{index}",
                    ground_truth=RedteamGroundTruthClass.NEGATIVE_CONTROL,
                    detected=False,
                    source_kind=RedteamBenchmarkSourceKind.DETERMINISTIC_REANALYSIS,
                ),
            )
        )
    observations.append(
        _policy_observation(
            profile_set,
            profile_id=REDTEAM_LLM_PROFILE,
            capability_id=llm_ids[0],
        )
    )

    rag_id = (
        profile_set.profile(REDTEAM_LLM_RAG_PROFILE)
        .capabilities[0]
        .capability.capability.capability_id
    )
    observations.extend(
        (
            _detection_observation(
                profile_set,
                profile_id=REDTEAM_LLM_RAG_PROFILE,
                capability_id=rag_id,
                label="rag-positive",
                ground_truth=RedteamGroundTruthClass.KNOWN_POSITIVE,
                detected=True,
                cost_usd=0.03,
            ),
            _replay_observation(
                profile_set,
                profile_id=REDTEAM_LLM_RAG_PROFILE,
                capability_id=rag_id,
                label="rag-replay",
                case_id="case:rag-positive",
            ),
            _detection_observation(
                profile_set,
                profile_id=REDTEAM_LLM_RAG_PROFILE,
                capability_id=rag_id,
                label="rag-negative",
                ground_truth=RedteamGroundTruthClass.NEGATIVE_CONTROL,
                detected=False,
                source_kind=RedteamBenchmarkSourceKind.DETERMINISTIC_REANALYSIS,
            ),
            _policy_observation(
                profile_set,
                profile_id=REDTEAM_LLM_RAG_PROFILE,
                capability_id=rag_id,
            ),
        )
    )

    web_id = (
        profile_set.profile(REDTEAM_WEB_PROFILE).capabilities[0].capability.capability.capability_id
    )
    web_negative = RedteamDetectionCaseObservation(
        caseId="case:web-negative-control",
        groundTruth=RedteamGroundTruthClass.NEGATIVE_CONTROL,
        detected=False,
        evidenceDigest=_digest("evidence:web-negative-control"),
    )
    observations.extend(
        (
            _detection_observation(
                profile_set,
                profile_id=REDTEAM_WEB_PROFILE,
                capability_id=web_id,
                label="web-positive",
                ground_truth=RedteamGroundTruthClass.KNOWN_POSITIVE,
                detected=True,
                extra_case=web_negative,
                cost_usd=0,
            ),
            _policy_observation(
                profile_set,
                profile_id=REDTEAM_WEB_PROFILE,
                capability_id=web_id,
            ),
        )
    )

    mcp_id = (
        profile_set.profile(REDTEAM_MCP_PROFILE).capabilities[0].capability.capability.capability_id
    )
    observations.extend(
        (
            _detection_observation(
                profile_set,
                profile_id=REDTEAM_MCP_PROFILE,
                capability_id=mcp_id,
                label="mcp-positive",
                ground_truth=RedteamGroundTruthClass.KNOWN_POSITIVE,
                detected=True,
                cost_usd=0,
            ),
            _policy_observation(
                profile_set,
                profile_id=REDTEAM_MCP_PROFILE,
                capability_id=mcp_id,
            ),
        )
    )
    return tuple(observations)


def _metric(
    report: RedteamInitialBenchmarkReport,
    profile_id: str,
    metric: RedteamBenchmarkMetric,
) -> RedteamBenchmarkMetricObservation:
    result = next(item for item in report.profile_results if item.profile_id == profile_id)
    return next(item for item in result.metrics if item.metric is metric)


def test_profile_set_binds_exact_redteam_inventory_and_applicability() -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())

    assert tuple(item.profile_id for item in profile_set.profiles) == (
        REDTEAM_LLM_PROFILE,
        REDTEAM_LLM_RAG_PROFILE,
        REDTEAM_WEB_PROFILE,
        REDTEAM_MCP_PROFILE,
    )
    assert len(profile_set.profile(REDTEAM_LLM_PROFILE).capabilities) == 2
    assert (
        profile_set.profile(REDTEAM_MCP_PROFILE).false_positive_measurement
        is RedteamMetricApplicability.NOT_APPLICABLE
    )
    assert (
        profile_set.profile(REDTEAM_WEB_PROFILE).replay_measurement
        is RedteamMetricApplicability.NOT_APPLICABLE
    )
    assert profile_set.security_domain_is_authority is False


def test_sealed_initial_benchmark_measures_available_metrics_without_finding_authority(
    tmp_path: Path,
) -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    recorder = RedteamBenchmarkRunObservationRecorder(output_root=tmp_path / "sources")
    sources = tuple(recorder.run(profile_set, item) for item in _observations(profile_set))

    outcome = RedteamInitialBenchmarkRunner(output_root=tmp_path / "reports").run(
        profile_set,
        sources,
        measured_at=NOW + timedelta(minutes=1),
    )
    report = load_redteam_initial_benchmark_report(
        profile_set,
        outcome,
        source_outcomes=sources,
    )

    assert report == outcome.report
    assert report.execution_authority_granted is False
    assert report.finding_authority_granted is False
    assert report.scope_expanded is False
    assert (
        _metric(
            report,
            REDTEAM_LLM_PROFILE,
            RedteamBenchmarkMetric.DETECTION_RECALL,
        ).value
        == 1
    )
    assert (
        _metric(
            report,
            REDTEAM_LLM_RAG_PROFILE,
            RedteamBenchmarkMetric.TOTAL_REQUEST_UNITS,
        ).value
        == 4
    )
    assert (
        _metric(
            report,
            REDTEAM_WEB_PROFILE,
            RedteamBenchmarkMetric.FALSE_POSITIVE_RATE,
        ).value
        == 0
    )
    assert (
        _metric(
            report,
            REDTEAM_MCP_PROFILE,
            RedteamBenchmarkMetric.FALSE_POSITIVE_RATE,
        ).status
        is RedteamBenchmarkMetricStatus.NOT_APPLICABLE
    )
    assert all(
        _metric(
            report,
            profile_id,
            RedteamBenchmarkMetric.TIME_TO_FIRST_VALID_FINDING,
        ).status
        is RedteamBenchmarkMetricStatus.NOT_APPLICABLE
        for profile_id in (
            REDTEAM_LLM_PROFILE,
            REDTEAM_LLM_RAG_PROFILE,
            REDTEAM_WEB_PROFILE,
            REDTEAM_MCP_PROFILE,
        )
    )


def test_initial_benchmark_rejects_missing_negative_replay_or_policy_coverage() -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    observations = _observations(profile_set)

    without_negative = tuple(
        item for item in observations if item.source_run_id != "source:rag-negative"
    )
    with pytest.raises(RedteamBenchmarkError, match="negative-control coverage"):
        aggregate_redteam_initial_benchmark(
            profile_set,
            without_negative,
            measured_at=NOW,
        )

    without_policy = tuple(
        item
        for item in observations
        if item.source_run_id != f"source:policy-{REDTEAM_WEB_PROFILE}"
    )
    with pytest.raises(RedteamBenchmarkError, match="policy-denial coverage"):
        aggregate_redteam_initial_benchmark(
            profile_set,
            without_policy,
            measured_at=NOW,
        )

    without_replay = tuple(
        item for item in observations if item.source_run_id != "source:rag-replay"
    )
    with pytest.raises(RedteamBenchmarkError, match="Replay coverage"):
        aggregate_redteam_initial_benchmark(
            profile_set,
            without_replay,
            measured_at=NOW,
        )

    rag_replay = next(item for item in observations if item.source_run_id == "source:rag-replay")
    same_source = rag_replay.model_dump(mode="json", by_alias=True)
    same_source.update(
        {
            "observationId": "",
            "observationDigest": "",
            "sourceRunId": "source:rag-positive",
        }
    )
    with pytest.raises(RedteamBenchmarkError, match="source Run identities"):
        aggregate_redteam_initial_benchmark(
            profile_set,
            tuple(
                RedteamBenchmarkRunObservation.model_validate(same_source)
                if item is rag_replay
                else item
                for item in observations
            ),
            measured_at=NOW,
        )


def test_observation_rejects_profile_authority_drift_and_finding_claims() -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    observations = _observations(profile_set)
    observation = observations[0]

    drifted = observation.model_dump(mode="json", by_alias=True)
    drifted["profileContractDigest"] = "f" * 64
    with pytest.raises(RedteamBenchmarkError, match="authority binding has drifted"):
        aggregate_redteam_initial_benchmark(
            profile_set,
            (
                RedteamBenchmarkRunObservation.model_validate(
                    {**drifted, "observationId": "", "observationDigest": ""}
                ),
            ),
            measured_at=NOW,
        )

    finding = observation.model_dump(mode="json", by_alias=True)
    finding["validFindingCount"] = 1
    with pytest.raises(ValidationError):
        RedteamBenchmarkRunObservation.model_validate(finding)

    replay = next(item for item in observations if item.source_run_id == "source:rag-replay")
    unsupported = replay.model_dump(mode="json", by_alias=True)
    unsupported["observationId"] = ""
    unsupported["observationDigest"] = ""
    unsupported_replay = unsupported["replayCases"][0]["observation"]
    unsupported_replay["observationId"] = ""
    unsupported_replay["observationDigest"] = ""
    unsupported_replay["contractId"] = "replay:unsupported"
    with pytest.raises(RedteamBenchmarkError, match="outside CAP-006 support"):
        aggregate_redteam_initial_benchmark(
            profile_set,
            (RedteamBenchmarkRunObservation.model_validate(unsupported),),
            measured_at=NOW,
        )


def test_report_loader_rejects_post_seal_source_mutation(tmp_path: Path) -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    recorder = RedteamBenchmarkRunObservationRecorder(output_root=tmp_path / "sources")
    sources = tuple(recorder.run(profile_set, item) for item in _observations(profile_set))
    outcome = RedteamInitialBenchmarkRunner(output_root=tmp_path / "reports").run(
        profile_set,
        sources,
        measured_at=NOW,
    )

    sources[0].run_path.joinpath(sources[0].artifact_path).write_text(
        "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(RedteamBenchmarkError, match="not sealed and valid"):
        load_redteam_initial_benchmark_report(
            profile_set,
            outcome,
            source_outcomes=sources,
        )


def test_product_flow_projects_verified_scope_evidence_and_measurement_without_findings(
    tmp_path: Path,
) -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    recorder = RedteamBenchmarkRunObservationRecorder(output_root=tmp_path / "sources")
    sources = tuple(recorder.run(profile_set, item) for item in _observations(profile_set))
    benchmark = RedteamInitialBenchmarkRunner(output_root=tmp_path / "reports").run(
        profile_set,
        sources,
        measured_at=NOW + timedelta(minutes=1),
    )

    outcome = RedteamProductFlowProjector(output_root=tmp_path / "product").project(
        profile_set,
        benchmark,
        source_outcomes=sources,
    )
    projection = load_redteam_product_flow(profile_set, outcome)

    assert projection == outcome.projection
    assert projection.measurement_report.report == benchmark.report
    assert tuple(item.profile_id for item in projection.scopes) == (
        REDTEAM_LLM_PROFILE,
        REDTEAM_LLM_RAG_PROFILE,
        REDTEAM_WEB_PROFILE,
        REDTEAM_MCP_PROFILE,
    )
    assert all(item.campaign_scope_available is False for item in projection.scopes)
    assert all(item.scope_authorized is False for item in projection.scopes)
    assert all(item.scope_expanded is False for item in projection.scopes)
    assert len(projection.evidence) == len(sources)
    assert all(item.sealed_source_verified is True for item in projection.evidence)
    assert all(item.evidence_content_included is False for item in projection.evidence)
    assert all(item.observation_is_finding is False for item in projection.evidence)
    assert all(item.confirmed_finding_count == 0 for item in projection.findings)
    assert all(item.validation_floor_satisfied is False for item in projection.findings)
    assert all(item.finding_confirmed is False for item in projection.findings)
    assert projection.measurement_report.finding_report_available is False
    assert projection.measurement_report.external_delivery_authorized is False
    assert projection.authority_boundary.campaign_profile_mapping_inferred is False
    assert projection.authority_boundary.scope_authority_granted is False
    assert projection.authority_boundary.finding_authority_granted is False
    assert projection.authority_boundary.execution_authorized is False
    assert any(
        case.detected
        for source in sources
        for case in source.observation.detection_cases
    )


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ("scopes", "scopeAuthorized", True),
        ("scopes", "profileDigest", "0" * 64),
        ("evidence", "observationIsFinding", True),
        ("evidence", "profileId", "redteam-unknown-v1"),
        (
            "evidence",
            "observationId",
            f"redteam-benchmark-observation:{'0' * 64}",
        ),
        ("findings", "campaignProfileMappingRegistered", True),
        ("findings", "validationFloorSatisfied", True),
        ("findings", "findingConfirmed", True),
        ("findings", "confirmedFindingCount", False),
        ("evidence", "sourceArtifactPath", "../outside.json"),
        ("measurementReport", "confirmedFindingCount", False),
        ("authorityBoundary", "scopeExpanded", True),
        ("authorityBoundary", "findingAuthorityGranted", True),
        ("authorityBoundary", "executionAuthorized", True),
        ("authorityBoundary", "findingAuthorityGranted", 0),
    ],
)
def test_product_flow_rejects_authority_escalation_or_boolean_coercion(
    section: str,
    field: str,
    replacement: object,
) -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    report = aggregate_redteam_initial_benchmark(
        profile_set,
        _observations(profile_set),
        measured_at=NOW,
    )
    observations = tuple(
        sorted(_observations(profile_set), key=lambda item: item.observation_digest)
    )
    payload = RedteamProductFlowProjection(
        profileSetDigest=report.profile_set.profile_set_digest,
        sourceObservationDigests=tuple(item.observation_digest for item in observations),
        scopes=tuple(
            {
                "profileId": profile.profile_id,
                "profileVersion": profile.profile_version,
                "profileDigest": profile.profile_digest,
                "profileContractDigest": profile.contract_digest,
                "capabilities": tuple(
                    sorted(
                        (item.capability for item in profile.capabilities),
                        key=lambda item: (
                            item.capability.capability_id,
                            item.capability.capability_version,
                        ),
                    )
                ),
                "sourceObservationCount": sum(
                    item.profile_id == profile.profile_id for item in observations
                ),
            }
            for profile in report.profile_set.profiles
        ),
        evidence=tuple(
            {
                "observationId": item.observation_id,
                "observationDigest": item.observation_digest,
                "profileId": item.profile_id,
                "capability": item.capability,
                "sourceKind": item.source_kind.value,
                "sourceRunId": item.source_run_id,
                "sourceRootDigest": item.source_root_digest,
                "sourceArtifactPath": item.source_artifact_path,
                "sourceArtifactSha256": item.source_artifact_sha256,
                "detectionCaseCount": len(item.detection_cases),
                "replayCaseCount": len(item.replay_cases),
                "evidenceExpectedCount": item.evidence_expected_count,
                "evidenceVerifiedCount": item.evidence_verified_count,
            }
            for item in observations
        ),
        findings=tuple(
            {
                "profileId": profile.profile_id,
                "sourceObservationCount": sum(
                    item.profile_id == profile.profile_id for item in observations
                ),
            }
            for profile in report.profile_set.profiles
        ),
        measurementReport={"report": report},
        authorityBoundary={},
    ).model_dump(mode="json", by_alias=True)

    target = payload[section]
    if isinstance(target, list):
        target = target[0]
    assert isinstance(target, dict)
    target[field] = replacement

    with pytest.raises(ValidationError):
        RedteamProductFlowProjection.model_validate(payload)


def test_product_flow_loader_rejects_post_seal_projection_or_source_mutation(
    tmp_path: Path,
) -> None:
    profile_set = registered_redteam_benchmark_profile_set(_bundle())
    recorder = RedteamBenchmarkRunObservationRecorder(output_root=tmp_path / "sources")
    sources = tuple(recorder.run(profile_set, item) for item in _observations(profile_set))
    benchmark = RedteamInitialBenchmarkRunner(output_root=tmp_path / "reports").run(
        profile_set,
        sources,
        measured_at=NOW + timedelta(minutes=1),
    )
    first = RedteamProductFlowProjector(output_root=tmp_path / "product-first").project(
        profile_set,
        benchmark,
        source_outcomes=sources,
    )
    (first.run_path / first.artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(RedteamProductFlowError, match="not sealed and reproducible"):
        load_redteam_product_flow(profile_set, first)

    second = RedteamProductFlowProjector(output_root=tmp_path / "product-second").project(
        profile_set,
        benchmark,
        source_outcomes=sources,
    )
    (sources[0].run_path / sources[0].artifact_path).write_text("{}", encoding="utf-8")
    with pytest.raises(RedteamProductFlowError, match="not sealed and reproducible"):
        load_redteam_product_flow(profile_set, second)
