from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_application_static_analysis_admission import _context

from pajin.benchmark.domain_metrics import (
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.discovery import ApplicationSurfaceClass
from pajin.domain.models import CampaignManifest
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow import application_reanalysis_benchmark
from pajin.workflow.application_reanalysis_benchmark import (
    ApplicationBenchmarkExpectedOutcome,
    ApplicationBenchmarkGroundTruthClass,
    ApplicationStaticAnalysisBenchmarkFixtureProfile,
    ApplicationStaticAnalysisReanalysisBenchmarkError,
    ApplicationStaticAnalysisReanalysisComparison,
    ApplicationStaticAnalysisReanalysisValidation,
    bind_application_static_analysis_reanalysis,
    load_verified_application_static_analysis_reanalysis_validation,
    registered_application_static_analysis_benchmark_fixture_profile,
)
from pajin.workflow.application_static_analysis_admission import (
    ApplicationStaticAnalysisExecutionTrustAnchor,
    ApplicationStaticAnalysisReviewSignal,
    application_static_analysis_execution_public_key,
    application_static_analysis_source_root_digest,
)


async def _admitted_pair(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: ApplicationSurfaceClass = ApplicationSurfaceClass.BINARY,
    source_signal: ApplicationStaticAnalysisReviewSignal | None | object = ...,
    reanalysis_signal: ApplicationStaticAnalysisReviewSignal | None | object = ...,
    source_body: bytes = b"deterministic-application-result",
    reanalysis_body: bytes = b"deterministic-application-result",
    source_result_size: int = 4_096,
    reanalysis_result_size: int = 4_096,
    reanalysis_offset: timedelta = timedelta(seconds=20),
):
    source = await _context(
        tmp_path / "source",
        sample_campaign,
        surface_class=surface_class,
        review_signal=source_signal,
        result_body=source_body,
        result_size=source_result_size,
        run_id="run_20260826T120000Z_applicationdsource",
        request_id="tool_application_reanalysis_source",
        execution_id="application-execution:reanalysis-source",
    )
    candidate = source.gate.prepare_candidate(source.source_inputs, source.graph_binding)
    admission = source.gate.admit(source.source_inputs, candidate)
    reanalysis = await _context(
        tmp_path / "reanalysis",
        sample_campaign,
        surface_class=surface_class,
        review_signal=reanalysis_signal,
        result_body=reanalysis_body,
        result_size=reanalysis_result_size,
        run_id="run_20260826T121000Z_applicationdreanalysis",
        request_id="tool_application_reanalysis_repeat",
        execution_id="application-execution:reanalysis-repeat",
        execution_offset=reanalysis_offset,
    )
    return source, admission, reanalysis


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_class", tuple(ApplicationSurfaceClass))
async def test_same_artifact_reanalysis_matches_without_new_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: ApplicationSurfaceClass,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
    )
    source_event_count = len(source.graph_store.event_log.events())
    reanalysis_event_count = len(reanalysis.graph_store.event_log.events())

    validation = bind_application_static_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is ApplicationStaticAnalysisReanalysisComparison.MATCHED
    assert validation.state == "deterministic-artifact-reanalysis-match"
    assert validation.result_body_digest_matched is True
    assert validation.result_bytes_matched is True
    assert validation.review_signal_matched is True
    assert validation.domain_validation_strategy_satisfied is True
    assert validation.deployment_context_reverification_required is True
    assert validation.self_authenticating_projection is False
    assert validation.source_execution.result_receipt.artifact_sha256 == (
        validation.reanalysis_execution.result_receipt.artifact_sha256
    )
    assert validation.source_execution.execution_bundle.statement.sandbox_runtime.parser == (
        validation.reanalysis_execution.execution_bundle.statement.sandbox_runtime.parser
    )
    assert validation.artifact_format_confirmed is False
    assert validation.vulnerability_confirmed is False
    assert validation.hypothesis_confirmed is False
    assert validation.benchmark_measurement_observed is False
    assert validation.finding_authority is False
    assert validation.replay_authorized is False
    assert validation.execution_authorized is False
    assert len(source.graph_store.event_log.events()) == source_event_count
    assert len(reanalysis.graph_store.event_log.events()) == reanalysis_event_count
    serialized = validation.model_dump_json(by_alias=True)
    assert "deterministic-application-result" not in serialized
    assert str(tmp_path) not in serialized
    plan = resolve_registered_domain_benchmark_plan(validation.domain_benchmark_plan)
    assert plan.domain_classification.domain is SecurityDomain.APPLICATION
    assert plan.validation_strategy is DomainValidationStrategy.DETERMINISTIC_ARTIFACT_REANALYSIS
    assert (
        ApplicationStaticAnalysisReanalysisValidation.model_validate(
            validation.model_dump(mode="json", by_alias=True)
        )
        == validation
    )


@pytest.mark.asyncio
async def test_bounded_signal_difference_is_changed_without_confirming_a_hypothesis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        reanalysis_signal=None,
        reanalysis_body=b"different-signaled-result",
        reanalysis_result_size=4_097,
    )

    validation = bind_application_static_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is ApplicationStaticAnalysisReanalysisComparison.CHANGED
    assert validation.state == "deterministic-artifact-reanalysis-changed"
    assert validation.result_body_digest_matched is False
    assert validation.result_bytes_matched is False
    assert validation.review_signal_matched is False
    assert validation.hypothesis_confirmed is False
    assert validation.vulnerability_confirmed is False


@pytest.mark.asyncio
async def test_opaque_digest_difference_without_signals_is_unresolved(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        source_signal=None,
        reanalysis_signal=None,
        source_body=b"opaque-result-a",
        reanalysis_body=b"opaque-result-b",
    )

    validation = bind_application_static_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is ApplicationStaticAnalysisReanalysisComparison.UNRESOLVED
    assert validation.state == "deterministic-artifact-reanalysis-unresolved"
    assert validation.result_body_digest_matched is False
    assert validation.result_bytes_matched is True
    assert validation.review_signal_matched is True
    assert validation.artifact_format_confirmed is False


@pytest.mark.asyncio
async def test_same_digest_with_different_signed_result_size_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        source_result_size=4_096,
        reanalysis_result_size=4_097,
    )

    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        bind_application_static_analysis_reanalysis(
            source.source_inputs,
            admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_source_authority_cannot_be_reused_as_reanalysis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, _ = await _admitted_pair(tmp_path, sample_campaign)

    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        bind_application_static_analysis_reanalysis(
            source.source_inputs,
            admission,
            source.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=source.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_each_separate_authority_coordinate_is_required(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, admission, reanalysis = await _admitted_pair(tmp_path, sample_campaign)
    validation = bind_application_static_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )
    expected_coordinates = {
        "runId",
        "sourceRootDigest",
        "requestId",
        "requestDigest",
        "envelopeId",
        "envelopeDigest",
        "proposalId",
        "proposalDigest",
        "decisionId",
        "decisionDigest",
        "permitId",
        "permitDigest",
        "dispatchId",
        "approvalId",
        "approvalDigest",
        "approvalReceiptId",
        "approvalReceiptDigest",
        "executionId",
        "statementSha256",
        "sandboxRuntimeReceiptId",
        "sandboxRuntimeReceiptDigest",
        "attestationSha256",
        "resultReceiptId",
        "resultReceiptDigest",
        "resultReceiptSha256",
    }
    source_coordinates = application_reanalysis_benchmark._execution_identity_coordinates(
        validation.source_execution
    )
    reanalysis_coordinates = application_reanalysis_benchmark._execution_identity_coordinates(
        validation.reanalysis_execution
    )

    assert set(source_coordinates) == expected_coordinates
    assert set(reanalysis_coordinates) == expected_coordinates
    assert all(
        source_coordinates[name] != reanalysis_coordinates[name] for name in expected_coordinates
    )
    real_coordinates = application_reanalysis_benchmark._execution_identity_coordinates
    for coordinate in expected_coordinates:
        collided = dict(reanalysis_coordinates)
        collided[coordinate] = source_coordinates[coordinate]
        coordinate_calls = iter((source_coordinates, collided))
        monkeypatch.setattr(
            application_reanalysis_benchmark,
            "_execution_identity_coordinates",
            lambda _execution, calls=coordinate_calls: next(calls),
        )
        with pytest.raises(ValueError, match=rf"reused.*{coordinate}"):
            application_reanalysis_benchmark._require_distinct_reanalysis_authority(
                validation.source_execution,
                validation.reanalysis_execution,
            )
    monkeypatch.setattr(
        application_reanalysis_benchmark,
        "_execution_identity_coordinates",
        real_coordinates,
    )


@pytest.mark.asyncio
async def test_distinct_but_noncausal_execution_is_not_reanalysis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        reanalysis_offset=timedelta(),
    )

    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        bind_application_static_analysis_reanalysis(
            source.source_inputs,
            admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_different_surface_artifact_cannot_be_compared(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, _ = await _admitted_pair(tmp_path / "binary", sample_campaign)
    foreign = await _context(
        tmp_path / "configuration",
        sample_campaign,
        surface_class=ApplicationSurfaceClass.CONFIGURATION,
        run_id="run_20260826T122000Z_applicationdforeign",
        request_id="tool_application_reanalysis_foreign",
        execution_id="application-execution:reanalysis-foreign",
        execution_offset=timedelta(seconds=20),
    )

    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        bind_application_static_analysis_reanalysis(
            source.source_inputs,
            admission,
            foreign.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=foreign.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_source_admission_must_be_stored_in_the_exact_source_graph(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, _, reanalysis = await _admitted_pair(tmp_path, sample_campaign)
    foreign = await _context(
        tmp_path / "foreign-admission",
        sample_campaign,
        run_id="run_20260826T120500Z_applicationdforeignadmission",
        request_id="tool_application_reanalysis_foreign_admission",
        execution_id="application-execution:reanalysis-foreign-admission",
    )
    foreign_candidate = foreign.gate.prepare_candidate(
        foreign.source_inputs,
        foreign.graph_binding,
    )
    foreign_admission = foreign.gate.admit(
        foreign.source_inputs,
        foreign_candidate,
    )

    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        bind_application_static_analysis_reanalysis(
            source.source_inputs,
            foreign_admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_validation_rejects_comparison_or_authority_marker_drift(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(tmp_path, sample_campaign)
    validation = bind_application_static_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )
    mutated = deepcopy(validation.model_dump(mode="json", by_alias=True))
    mutated["validationId"] = ""
    mutated["validationDigest"] = ""
    mutated["resultBodyDigestMatched"] = False
    with pytest.raises(ValidationError, match="comparison differs"):
        ApplicationStaticAnalysisReanalysisValidation.model_validate(mutated)

    bytes_mutated = deepcopy(validation.model_dump(mode="json", by_alias=True))
    bytes_mutated["validationId"] = ""
    bytes_mutated["validationDigest"] = ""
    bytes_mutated["resultBytesMatched"] = False
    with pytest.raises(ValidationError, match="comparison differs"):
        ApplicationStaticAnalysisReanalysisValidation.model_validate(bytes_mutated)

    coerced = deepcopy(validation.model_dump(mode="json", by_alias=True))
    coerced["validationId"] = ""
    coerced["validationDigest"] = ""
    coerced["resultBytesMatched"] = 1
    with pytest.raises(ValidationError, match="comparison markers"):
        ApplicationStaticAnalysisReanalysisValidation.model_validate(coerced)

    escalated = deepcopy(validation.model_dump(mode="json", by_alias=True))
    escalated["validationId"] = ""
    escalated["validationDigest"] = ""
    escalated["executionAuthorized"] = 1
    with pytest.raises(ValidationError, match="authority markers"):
        ApplicationStaticAnalysisReanalysisValidation.model_validate(escalated)

    stale_identity = deepcopy(validation.model_dump(mode="json", by_alias=True))
    stale_identity["validationDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="validation digest differs"):
        ApplicationStaticAnalysisReanalysisValidation.model_validate(stale_identity)


def test_seeded_fixture_profile_registers_each_positive_and_negative_control() -> None:
    profile = registered_application_static_analysis_benchmark_fixture_profile()

    assert profile.state == "registered-seeded-ground-truth-not-measured"
    assert profile.covered_surface_classes == tuple(ApplicationSurfaceClass)
    assert len(profile.cases) == 8
    assert [case.fixture_id for case in profile.cases] == sorted(
        case.fixture_id for case in profile.cases
    )
    assert {case.surface_class for case in profile.cases} == set(ApplicationSurfaceClass)
    for surface_class in ApplicationSurfaceClass:
        cases = tuple(case for case in profile.cases if case.surface_class is surface_class)
        assert {case.ground_truth_class for case in cases} == {
            ApplicationBenchmarkGroundTruthClass.KNOWN_POSITIVE,
            ApplicationBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
        }
        positive = next(
            case
            for case in cases
            if case.ground_truth_class is ApplicationBenchmarkGroundTruthClass.KNOWN_POSITIVE
        )
        negative = next(
            case
            for case in cases
            if case.ground_truth_class is ApplicationBenchmarkGroundTruthClass.NEGATIVE_CONTROL
        )
        assert positive.expected_outcome is ApplicationBenchmarkExpectedOutcome.REVIEW_SIGNAL
        assert positive.expected_review_signal is not None
        assert negative.expected_outcome is ApplicationBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
        assert negative.expected_review_signal is None
    assert all("cleanup-receipt" in case.required_evidence for case in profile.cases)
    assert profile.disposable_sandbox_required is True
    assert profile.network_disabled_required is True
    assert profile.read_only_noexec_artifact_mount_required is True
    assert profile.private_ground_truth_requirements_registered is True
    assert profile.private_ground_truth_verified is False
    assert profile.artifact_fixture_materialized is False
    assert profile.sandbox_provisioned is False
    assert profile.provider_execution_authorized is False
    assert profile.fixture_execution_authorized is False
    assert profile.cleanup_observed is False
    assert profile.artifact_analysis_coverage_measured is False
    assert profile.configuration_value_confirmed is False
    assert profile.runtime_support_confirmed is False
    assert profile.dependency_relationship_confirmed is False
    assert profile.vulnerability_confirmed is False
    assert profile.negative_control_observed is False
    assert profile.profile_validation_floor_satisfied is False
    assert profile.execution_authorized is False
    assert (
        ApplicationStaticAnalysisBenchmarkFixtureProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        == profile
    )

    mutated = deepcopy(profile.model_dump(mode="json", by_alias=True))
    mutated["profileId"] = ""
    mutated["profileDigest"] = ""
    mutated["cases"][0]["surfaceClass"] = ApplicationSurfaceClass.RUNTIME.value
    with pytest.raises(ValidationError, match=r"Ground Truth|profile differs"):
        ApplicationStaticAnalysisBenchmarkFixtureProfile.model_validate(mutated)

    evidence_drift = deepcopy(profile.model_dump(mode="json", by_alias=True))
    evidence_drift["profileId"] = ""
    evidence_drift["profileDigest"] = ""
    evidence_drift["cases"][0]["requiredEvidence"] = list(
        reversed(evidence_drift["cases"][0]["requiredEvidence"])
    )
    with pytest.raises(ValidationError, match="Ground Truth"):
        ApplicationStaticAnalysisBenchmarkFixtureProfile.model_validate(evidence_drift)

    foreign_plan = next(
        plan
        for plan in registered_domain_benchmark_registry().plans
        if plan.domain_classification.domain is SecurityDomain.SYSTEM
    )
    plan_drift = deepcopy(profile.model_dump(mode="json", by_alias=True))
    plan_drift["profileId"] = ""
    plan_drift["profileDigest"] = ""
    plan_drift["domainBenchmarkPlan"] = foreign_plan.reference().model_dump(
        mode="json",
        by_alias=True,
    )
    with pytest.raises(ValidationError, match="Domain benchmark strategy"):
        ApplicationStaticAnalysisBenchmarkFixtureProfile.model_validate(plan_drift)

    escalated = deepcopy(profile.model_dump(mode="json", by_alias=True))
    escalated["profileId"] = ""
    escalated["profileDigest"] = ""
    escalated["executionAuthorized"] = 1
    with pytest.raises(ValidationError, match="authority markers"):
        ApplicationStaticAnalysisBenchmarkFixtureProfile.model_validate(escalated)

    stale_identity = deepcopy(profile.model_dump(mode="json", by_alias=True))
    stale_identity["profileDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="profile digest differs"):
        ApplicationStaticAnalysisBenchmarkFixtureProfile.model_validate(stale_identity)


@pytest.mark.asyncio
async def test_contextful_wire_loader_rechecks_evidence_graph_and_external_trust_anchor(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(tmp_path, sample_campaign)
    validation = bind_application_static_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )
    wire = validation.model_dump(mode="json", by_alias=True)

    assert (
        load_verified_application_static_analysis_reanalysis_validation(
            wire,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )
        == validation
    )

    coerced_verification = deepcopy(wire)
    coerced_verification["sourceExecution"]["verification"]["valid"] = 1
    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        load_verified_application_static_analysis_reanalysis_validation(
            coerced_verification,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
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
    forged_event["occurredAt"] = "2026-08-26T12:59:59Z"
    canonical_forged_event = type(admission.observation_graph_event).model_validate(forged_event)
    forged_hypothesis_event = forged_graph["sourceAdmission"]["hypothesisGraphEvent"]
    assert forged_hypothesis_event is not None
    forged_hypothesis_event["eventId"] = ""
    forged_hypothesis_event["eventDigest"] = ""
    forged_hypothesis_event["previousEventDigest"] = canonical_forged_event.event_digest
    forged_graph_model = ApplicationStaticAnalysisReanalysisValidation.model_validate(forged_graph)
    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        load_verified_application_static_analysis_reanalysis_validation(
            forged_graph_model,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )

    forged_attestation = deepcopy(wire)
    forged_attestation["validationId"] = ""
    forged_attestation["validationDigest"] = ""
    execution = forged_attestation["reanalysisExecution"]
    execution["attestationSha256"] = "f" * 64
    execution["sourceRootDigest"] = application_static_analysis_source_root_digest(
        attestation_sha256=execution["attestationSha256"],
        result_receipt_sha256=execution["resultReceiptSha256"],
        trust_anchor_digest=execution["verification"]["trustAnchorDigest"],
        statement_sha256=execution["verification"]["statementSha256"],
    )
    forged_attestation_model = ApplicationStaticAnalysisReanalysisValidation.model_validate(
        forged_attestation
    )
    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="wire re-verification failed closed",
    ):
        load_verified_application_static_analysis_reanalysis_validation(
            forged_attestation_model,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )

    foreign_anchor_payload = source.trust_anchor.model_dump(mode="json", by_alias=True)
    foreign_anchor_payload["keys"][0]["publicKeyBase64url"] = (
        application_static_analysis_execution_public_key(
            sha256(b"APP-001D foreign deployment trust anchor").digest()
        )
    )
    foreign_anchor = ApplicationStaticAnalysisExecutionTrustAnchor.model_validate(
        foreign_anchor_payload
    )
    with pytest.raises(
        ApplicationStaticAnalysisReanalysisBenchmarkError,
        match="failed closed",
    ):
        load_verified_application_static_analysis_reanalysis_validation(
            wire,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=foreign_anchor,
        )
