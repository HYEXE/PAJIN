from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
import test_mobile_package_analysis_admission as mobile_admission_tests
from pydantic import ValidationError
from test_mobile_package_analysis import _campaign as mobile_campaign
from test_mobile_package_analysis import _custody, _sandbox
from test_mobile_package_analysis_admission import _Context, _context

from pajin.benchmark.domain_metrics import (
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.capabilities.mobile_package_analysis import (
    MobilePackageAnalysisSandboxBinding,
    MobilePackageParser,
    bind_mobile_package_analysis_sandbox,
)
from pajin.discovery import (
    MobileApplicationRuntimeSurface,
    MobilePlatform,
    MobileSurfaceClass,
)
from pajin.domain.models import CampaignManifest
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow import mobile_package_reanalysis_benchmark
from pajin.workflow.mobile_package_analysis_admission import (
    MobilePackageAnalysisExecutionTrustAnchor,
    MobilePackageAnalysisKnowledgeAdmission,
    MobilePackageAnalysisReviewSignal,
    mobile_package_analysis_execution_public_key,
    mobile_package_analysis_source_root_digest,
)
from pajin.workflow.mobile_package_reanalysis_benchmark import (
    MobileBenchmarkExpectedOutcome,
    MobileBenchmarkGroundTruthClass,
    MobilePackageAnalysisBenchmarkFixtureCase,
    MobilePackageAnalysisBenchmarkFixtureProfile,
    MobilePackageAnalysisReanalysisBenchmarkError,
    MobilePackageAnalysisReanalysisComparison,
    MobilePackageAnalysisReanalysisValidation,
    bind_mobile_package_analysis_reanalysis,
    load_verified_mobile_package_analysis_reanalysis_validation,
    registered_mobile_package_analysis_benchmark_fixture_profile,
)

_VALID_LINEAGES = (
    (MobileSurfaceClass.APK, MobilePlatform.ANDROID),
    (MobileSurfaceClass.IPA, MobilePlatform.IOS),
    (MobileSurfaceClass.APPLICATION, MobilePlatform.ANDROID),
    (MobileSurfaceClass.APPLICATION, MobilePlatform.IOS),
    (MobileSurfaceClass.RUNTIME, MobilePlatform.ANDROID),
    (MobileSurfaceClass.RUNTIME, MobilePlatform.IOS),
    (MobileSurfaceClass.STORAGE, MobilePlatform.ANDROID),
    (MobileSurfaceClass.STORAGE, MobilePlatform.IOS),
    (MobileSurfaceClass.DEEPLINK, MobilePlatform.ANDROID),
    (MobileSurfaceClass.DEEPLINK, MobilePlatform.IOS),
    (MobileSurfaceClass.TLS, MobilePlatform.ANDROID),
    (MobileSurfaceClass.TLS, MobilePlatform.IOS),
    (MobileSurfaceClass.AUTH, MobilePlatform.ANDROID),
    (MobileSurfaceClass.AUTH, MobilePlatform.IOS),
)


def _root_class(platform: MobilePlatform) -> MobileSurfaceClass:
    return MobileSurfaceClass.APK if platform is MobilePlatform.ANDROID else MobileSurfaceClass.IPA


def _parser(platform: MobilePlatform) -> MobilePackageParser:
    return (
        MobilePackageParser.ANDROID_APK_STRUCTURE
        if platform is MobilePlatform.ANDROID
        else MobilePackageParser.IOS_IPA_STRUCTURE
    )


def _signal(surface_class: MobileSurfaceClass) -> MobilePackageAnalysisReviewSignal:
    return {
        MobileSurfaceClass.APK: (MobilePackageAnalysisReviewSignal.APK_PACKAGE_STRUCTURE_REVIEW),
        MobileSurfaceClass.IPA: (MobilePackageAnalysisReviewSignal.IPA_PACKAGE_STRUCTURE_REVIEW),
        MobileSurfaceClass.APPLICATION: (
            MobilePackageAnalysisReviewSignal.APPLICATION_DECLARATION_REVIEW
        ),
        MobileSurfaceClass.RUNTIME: (MobilePackageAnalysisReviewSignal.RUNTIME_DECLARATION_REVIEW),
        MobileSurfaceClass.STORAGE: (MobilePackageAnalysisReviewSignal.STORAGE_DECLARATION_REVIEW),
        MobileSurfaceClass.DEEPLINK: (
            MobilePackageAnalysisReviewSignal.DEEP_LINK_DECLARATION_REVIEW
        ),
        MobileSurfaceClass.TLS: (MobilePackageAnalysisReviewSignal.TLS_POLICY_DECLARATION_REVIEW),
        MobileSurfaceClass.AUTH: (
            MobilePackageAnalysisReviewSignal.AUTHENTICATION_FLOW_DECLARATION_REVIEW
        ),
    }[surface_class]


async def _admitted_pair(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: MobileSurfaceClass = MobileSurfaceClass.APK,
    platform: MobilePlatform = MobilePlatform.ANDROID,
    source_signal: MobilePackageAnalysisReviewSignal | None | object = ...,
    reanalysis_signal: MobilePackageAnalysisReviewSignal | None | object = ...,
    source_body: bytes = b"deterministic-mobile-package-result",
    reanalysis_body: bytes = b"deterministic-mobile-package-result",
    source_result_size: int = 4_096,
    reanalysis_result_size: int = 4_096,
    reanalysis_offset: timedelta = timedelta(seconds=20),
    reanalysis_runtime_update: dict[str, object] | None = None,
) -> tuple[_Context, MobilePackageAnalysisKnowledgeAdmission, _Context]:
    source = await _context(
        tmp_path / "source",
        sample_campaign,
        surface_class=surface_class,
        platform=platform,
        review_signal=source_signal,
        result_size=source_result_size,
        result_body=source_body,
        run_id="run_20260827T150000Z_mobiledsource",
        request_id="tool_mobile_package_reanalysis_source",
        execution_id="mobile-execution:reanalysis-source",
    )
    candidate = source.gate.prepare_candidate(source.source_inputs, source.graph_binding)
    admission = source.gate.admit(source.source_inputs, candidate)
    reanalysis = await _context(
        tmp_path / "reanalysis",
        sample_campaign,
        surface_class=surface_class,
        platform=platform,
        review_signal=reanalysis_signal,
        result_size=reanalysis_result_size,
        result_body=reanalysis_body,
        run_id="run_20260827T151000Z_mobiledreanalysis",
        request_id="tool_mobile_package_reanalysis_repeat",
        execution_id="mobile-execution:reanalysis-repeat",
        execution_offset=reanalysis_offset,
        runtime_update=reanalysis_runtime_update,
    )
    return source, admission, reanalysis


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("surface_class", "platform"),
    _VALID_LINEAGES,
    ids=(
        "apk-android",
        "ipa-ios",
        "application-android",
        "application-ios",
        "runtime-android",
        "runtime-ios",
        "storage-android",
        "storage-ios",
        "deeplink-android",
        "deeplink-ios",
        "tls-android",
        "tls-ios",
        "auth-android",
        "auth-ios",
    ),
)
async def test_all_valid_mobile_lineages_match_without_new_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: MobileSurfaceClass,
    platform: MobilePlatform,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        platform=platform,
    )
    source_event_count = len(source.graph_store.event_log.events())
    reanalysis_event_count = len(reanalysis.graph_store.event_log.events())

    validation = bind_mobile_package_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is MobilePackageAnalysisReanalysisComparison.MATCHED
    assert validation.state == "deterministic-package-reanalysis-match"
    assert validation.result_body_digest_matched is True
    assert validation.result_bytes_matched is True
    assert validation.review_signal_matched is True
    assert validation.domain_validation_strategy_satisfied is True
    assert validation.deployment_context_reverification_required is True
    assert validation.self_authenticating_projection is False
    assert validation.domain_worker_profile_binding_deferred is True
    assert validation.source_execution.result_receipt.surface.surface_class is surface_class
    assert validation.source_execution.result_receipt.package_surface.surface_class is _root_class(
        platform
    )
    assert validation.source_execution.result_receipt.platform is platform
    assert validation.source_execution.result_receipt.parser is _parser(platform)
    assert validation.reanalysis_execution.result_receipt.surface == (
        validation.source_execution.result_receipt.surface
    )
    assert validation.reanalysis_execution.result_receipt.package_surface == (
        validation.source_execution.result_receipt.package_surface
    )
    assert validation.package_format_confirmed is False
    assert validation.manifest_truth_confirmed is False
    assert validation.vulnerability_confirmed is False
    assert validation.hypothesis_confirmed is False
    assert validation.ground_truth_case_bound is False
    assert validation.manifest_component_coverage_measured is False
    assert validation.domain_worker_profile_bound is False
    assert validation.emulator_or_device_access_authorized is False
    assert validation.replay_authorized is False
    assert validation.execution_authorized is False
    assert len(source.graph_store.event_log.events()) == source_event_count
    assert len(reanalysis.graph_store.event_log.events()) == reanalysis_event_count
    serialized = validation.model_dump_json(by_alias=True)
    assert "deterministic-mobile-package-result" not in serialized
    assert str(tmp_path) not in serialized
    plan = resolve_registered_domain_benchmark_plan(validation.domain_benchmark_plan)
    assert plan.domain_classification.domain is SecurityDomain.MOBILE
    assert plan.validation_strategy is DomainValidationStrategy.DETERMINISTIC_PACKAGE_REANALYSIS
    assert (
        MobilePackageAnalysisReanalysisValidation.model_validate(
            validation.model_dump(mode="json", by_alias=True)
        )
        == validation
    )


@pytest.mark.asyncio
async def test_signal_difference_is_changed_without_mobile_truth(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        reanalysis_signal=None,
        reanalysis_body=b"different-signaled-mobile-result",
        reanalysis_result_size=4_097,
        reanalysis_runtime_update={
            "runtimeIdentityDigest": sha256(b"fresh-mobile-runtime-identity").hexdigest(),
            "confinementDigest": sha256(b"fresh-mobile-confinement").hexdigest(),
        },
    )

    validation = bind_mobile_package_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is MobilePackageAnalysisReanalysisComparison.CHANGED
    assert validation.state == "deterministic-package-reanalysis-changed"
    assert validation.result_body_digest_matched is False
    assert validation.result_bytes_matched is False
    assert validation.review_signal_matched is False
    assert validation.vulnerability_confirmed is False
    assert validation.hypothesis_confirmed is False


@pytest.mark.asyncio
async def test_opaque_digest_difference_without_signals_is_unresolved(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(
        tmp_path,
        sample_campaign,
        surface_class=MobileSurfaceClass.RUNTIME,
        platform=MobilePlatform.IOS,
        source_signal=None,
        reanalysis_signal=None,
        source_body=b"opaque-mobile-result-a",
        reanalysis_body=b"opaque-mobile-result-b",
    )

    validation = bind_mobile_package_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )

    assert validation.comparison is MobilePackageAnalysisReanalysisComparison.UNRESOLVED
    assert validation.state == "deterministic-package-reanalysis-unresolved"
    assert validation.result_body_digest_matched is False
    assert validation.result_bytes_matched is True
    assert validation.review_signal_matched is True
    assert validation.negative_control_observed is False


@pytest.mark.asyncio
async def test_source_authority_cannot_be_reused_as_reanalysis(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, _ = await _admitted_pair(tmp_path, sample_campaign)

    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        bind_mobile_package_analysis_reanalysis(
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
    validation = bind_mobile_package_analysis_reanalysis(
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
    source_coordinates = mobile_package_reanalysis_benchmark._execution_identity_coordinates(
        validation.source_execution
    )
    reanalysis_coordinates = mobile_package_reanalysis_benchmark._execution_identity_coordinates(
        validation.reanalysis_execution
    )

    assert set(source_coordinates) == expected_coordinates
    assert set(reanalysis_coordinates) == expected_coordinates
    assert all(
        source_coordinates[name] != reanalysis_coordinates[name] for name in expected_coordinates
    )
    real_coordinates = mobile_package_reanalysis_benchmark._execution_identity_coordinates
    for coordinate in expected_coordinates:
        collided = dict(reanalysis_coordinates)
        collided[coordinate] = source_coordinates[coordinate]
        coordinate_calls = iter((source_coordinates, collided))
        monkeypatch.setattr(
            mobile_package_reanalysis_benchmark,
            "_execution_identity_coordinates",
            lambda _execution, calls=coordinate_calls: next(calls),
        )
        with pytest.raises(ValueError, match=rf"reused.*{coordinate}"):
            mobile_package_reanalysis_benchmark._require_distinct_reanalysis_authority(
                validation.source_execution,
                validation.reanalysis_execution,
            )
    monkeypatch.setattr(
        mobile_package_reanalysis_benchmark,
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

    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        bind_mobile_package_analysis_reanalysis(
            source.source_inputs,
            admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_selected_surface_or_android_ios_root_semantics_cannot_be_compared(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, _ = await _admitted_pair(
        tmp_path / "source-pair",
        sample_campaign,
        surface_class=MobileSurfaceClass.RUNTIME,
        platform=MobilePlatform.ANDROID,
    )
    foreign_inputs = (
        (MobileSurfaceClass.TLS, MobilePlatform.ANDROID, "selected"),
        (MobileSurfaceClass.RUNTIME, MobilePlatform.IOS, "root-platform-parser"),
    )
    for surface_class, platform, label in foreign_inputs:
        foreign = await _context(
            tmp_path / label,
            sample_campaign,
            surface_class=surface_class,
            platform=platform,
            run_id=f"run_20260827T152000Z_mobiled{label.replace('-', '')}",
            request_id=f"tool_mobile_reanalysis_{label.replace('-', '_')}",
            execution_id=f"mobile-execution:reanalysis-{label}",
            execution_offset=timedelta(seconds=20),
        )
        with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
            bind_mobile_package_analysis_reanalysis(
                source.source_inputs,
                admission,
                foreign.source_inputs,
                source_graph_store=source.graph_store,
                reanalysis_graph_store=foreign.graph_store,
                trust_anchor=source.trust_anchor,
            )


@pytest.mark.asyncio
async def test_custody_sandbox_scope_budget_or_archive_configuration_drift_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, admission, _ = await _admitted_pair(tmp_path / "source-pair", sample_campaign)

    async def require_foreign_failure(label: str) -> None:
        foreign = await _context(
            tmp_path / label,
            sample_campaign,
            run_id=f"run_20260827T153000Z_mobiled{label}",
            request_id=f"tool_mobile_reanalysis_{label}",
            execution_id=f"mobile-execution:reanalysis-{label}",
            execution_offset=timedelta(seconds=20),
        )
        with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
            bind_mobile_package_analysis_reanalysis(
                source.source_inputs,
                admission,
                foreign.source_inputs,
                source_graph_store=source.graph_store,
                reanalysis_graph_store=foreign.graph_store,
                trust_anchor=source.trust_anchor,
            )

    monkeypatch.setattr(
        mobile_admission_tests,
        "_custody",
        lambda surface: _custody(surface, artifact_bytes=8_192),
    )
    await require_foreign_failure("custody")
    monkeypatch.setattr(mobile_admission_tests, "_custody", _custody)

    def changed_sandbox(
        surface: MobileApplicationRuntimeSurface,
    ) -> MobilePackageAnalysisSandboxBinding:
        canonical = _sandbox(surface)
        return bind_mobile_package_analysis_sandbox(
            deployment_id=canonical.deployment_id,
            surface=surface,
            operation=canonical.operation,
            parser_executable_sha256=canonical.parser_executable_sha256,
            sandbox_image_sha256=canonical.sandbox_image_sha256,
            run_as_identity=canonical.run_as_identity,
            max_artifact_bytes=canonical.max_artifact_bytes,
            max_output_bytes=canonical.max_output_bytes,
            max_runtime_seconds=canonical.max_runtime_seconds + 1,
            max_memory_mib=canonical.max_memory_mib,
            max_process_count=canonical.max_process_count,
            max_archive_entries=canonical.max_archive_entries + 1,
            max_total_uncompressed_bytes=canonical.max_total_uncompressed_bytes,
            max_single_uncompressed_bytes=canonical.max_single_uncompressed_bytes,
            max_archive_path_bytes=canonical.max_archive_path_bytes,
            max_archive_nesting_depth=canonical.max_archive_nesting_depth,
            max_compression_ratio=canonical.max_compression_ratio,
        )

    monkeypatch.setattr(mobile_admission_tests, "_sandbox", changed_sandbox)
    await require_foreign_failure("sandbox")
    monkeypatch.setattr(mobile_admission_tests, "_sandbox", _sandbox)

    real_campaign = mobile_campaign

    def changed_campaign(
        campaign: CampaignManifest,
        *,
        surface: MobileApplicationRuntimeSurface,
    ) -> CampaignManifest:
        return real_campaign(campaign, surface=surface, allow_private=True)

    monkeypatch.setattr(mobile_admission_tests, "_campaign", changed_campaign)
    await require_foreign_failure("scope")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift_kind",
    (
        "archive-observation",
        "same-digest-result-bytes",
    ),
)
async def test_archive_observation_or_same_digest_result_size_drift_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    drift_kind: str,
) -> None:
    if drift_kind == "archive-observation":
        source, admission, reanalysis = await _admitted_pair(
            tmp_path / drift_kind,
            sample_campaign,
            reanalysis_runtime_update={"observedArchiveEntries": 33},
        )
    else:
        source, admission, reanalysis = await _admitted_pair(
            tmp_path / drift_kind,
            sample_campaign,
            source_result_size=4_096,
            reanalysis_result_size=4_097,
        )
    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        bind_mobile_package_analysis_reanalysis(
            source.source_inputs,
            admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_source_admission_must_be_stored_in_the_exact_source_graph(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, _, reanalysis = await _admitted_pair(tmp_path / "pair", sample_campaign)
    foreign = await _context(
        tmp_path / "foreign-admission",
        sample_campaign,
        run_id="run_20260827T154000Z_mobiledforeign",
        request_id="tool_mobile_reanalysis_foreign_admission",
        execution_id="mobile-execution:reanalysis-foreign-admission",
    )
    foreign_candidate = foreign.gate.prepare_candidate(
        foreign.source_inputs,
        foreign.graph_binding,
    )
    foreign_admission = foreign.gate.admit(foreign.source_inputs, foreign_candidate)

    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        bind_mobile_package_analysis_reanalysis(
            source.source_inputs,
            foreign_admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


@pytest.mark.asyncio
async def test_validation_rejects_comparison_coercion_authority_and_unknown_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(tmp_path, sample_campaign)
    validation = bind_mobile_package_analysis_reanalysis(
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
        MobilePackageAnalysisReanalysisValidation.model_validate(mutated)

    coerced = deepcopy(validation.model_dump(mode="json", by_alias=True))
    coerced["validationId"] = ""
    coerced["validationDigest"] = ""
    coerced["resultBodyDigestMatched"] = 1
    with pytest.raises(ValidationError, match="comparison markers"):
        MobilePackageAnalysisReanalysisValidation.model_validate(coerced)

    escalated = deepcopy(validation.model_dump(mode="json", by_alias=True))
    escalated["validationId"] = ""
    escalated["validationDigest"] = ""
    escalated["executionAuthorized"] = 1
    with pytest.raises(ValidationError, match="authority markers"):
        MobilePackageAnalysisReanalysisValidation.model_validate(escalated)

    forged_validation = validation.model_copy(update={"unmodeledAuthority": True})
    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        load_verified_mobile_package_analysis_reanalysis_validation(
            forged_validation,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )

    forged_admission = admission.model_copy(update={"unmodeledAuthority": True})
    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        bind_mobile_package_analysis_reanalysis(
            source.source_inputs,
            forged_admission,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )


def test_seeded_fixture_profile_registers_exact_28_lineage_controls() -> None:
    profile = registered_mobile_package_analysis_benchmark_fixture_profile()

    assert profile.state == "registered-seeded-ground-truth-not-measured"
    assert profile.covered_surface_classes == tuple(MobileSurfaceClass)
    assert profile.covered_platforms == tuple(MobilePlatform)
    assert len(profile.cases) == 28
    assert [case.fixture_id for case in profile.cases] == sorted(
        case.fixture_id for case in profile.cases
    )
    valid_lineages = {
        (surface_class, platform, _root_class(platform))
        for surface_class, platform in _VALID_LINEAGES
    }
    assert {
        (case.selected_surface_class, case.platform, case.package_surface_class)
        for case in profile.cases
    } == valid_lineages
    for surface_class, platform, package_surface_class in valid_lineages:
        cases = tuple(
            case
            for case in profile.cases
            if (
                case.selected_surface_class,
                case.platform,
                case.package_surface_class,
            )
            == (surface_class, platform, package_surface_class)
        )
        assert len(cases) == 2
        assert {case.ground_truth_class for case in cases} == {
            MobileBenchmarkGroundTruthClass.KNOWN_POSITIVE,
            MobileBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
        }
        positive = next(
            case
            for case in cases
            if case.ground_truth_class is MobileBenchmarkGroundTruthClass.KNOWN_POSITIVE
        )
        negative = next(
            case
            for case in cases
            if case.ground_truth_class is MobileBenchmarkGroundTruthClass.NEGATIVE_CONTROL
        )
        assert positive.expected_outcome is MobileBenchmarkExpectedOutcome.REVIEW_SIGNAL
        assert positive.expected_review_signal is _signal(surface_class)
        assert negative.expected_outcome is MobileBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
        assert negative.expected_review_signal is None
        assert positive.required_evidence == negative.required_evidence
        assert "cleanup-receipt" in positive.required_evidence

    assert profile.disposable_static_sandbox_required is True
    assert profile.network_and_dns_disabled_required is True
    assert profile.non_root_runtime_required is True
    assert profile.read_only_noexec_package_mount_required is True
    assert profile.private_ground_truth_requirements_registered is True
    assert profile.private_ground_truth_verified is False
    assert profile.package_fixture_materialized is False
    assert profile.sandbox_provisioned is False
    assert profile.cleanup_observed is False
    assert profile.reanalysis_evidence_bound is False
    assert profile.manifest_component_coverage_measured is False
    assert profile.domain_worker_profile_bound is False
    assert profile.device_bound_runtime_profile_applied is False
    assert profile.emulator_or_device_access_authorized is False
    assert profile.execution_authorized is False
    assert (
        MobilePackageAnalysisBenchmarkFixtureProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        == profile
    )

    mutated = deepcopy(profile.model_dump(mode="json", by_alias=True))
    mutated["profileId"] = ""
    mutated["profileDigest"] = ""
    mutated["cases"][0]["platform"] = (
        MobilePlatform.IOS.value
        if mutated["cases"][0]["platform"] == MobilePlatform.ANDROID.value
        else MobilePlatform.ANDROID.value
    )
    with pytest.raises(ValidationError, match=r"Ground Truth|profile differs"):
        MobilePackageAnalysisBenchmarkFixtureProfile.model_validate(mutated)

    signal_drift = deepcopy(profile.model_dump(mode="json", by_alias=True))
    signal_drift["profileId"] = ""
    signal_drift["profileDigest"] = ""
    positive_index = next(
        index for index, case in enumerate(profile.cases) if case.expected_review_signal is not None
    )
    signal_drift["cases"][positive_index]["expectedReviewSignal"] = (
        MobilePackageAnalysisReviewSignal.AUTHENTICATION_FLOW_DECLARATION_REVIEW.value
    )
    with pytest.raises(ValidationError, match=r"Ground Truth|profile differs"):
        MobilePackageAnalysisBenchmarkFixtureProfile.model_validate(signal_drift)

    foreign_plan = next(
        plan
        for plan in registered_domain_benchmark_registry().plans
        if plan.domain_classification.domain is SecurityDomain.APPLICATION
    )
    plan_drift = deepcopy(profile.model_dump(mode="json", by_alias=True))
    plan_drift["profileId"] = ""
    plan_drift["profileDigest"] = ""
    plan_drift["domainBenchmarkPlan"] = foreign_plan.reference().model_dump(
        mode="json",
        by_alias=True,
    )
    with pytest.raises(ValidationError, match="Domain benchmark strategy"):
        MobilePackageAnalysisBenchmarkFixtureProfile.model_validate(plan_drift)

    escalated = deepcopy(profile.model_dump(mode="json", by_alias=True))
    escalated["profileId"] = ""
    escalated["profileDigest"] = ""
    escalated["executionAuthorized"] = 1
    with pytest.raises(ValidationError, match="authority markers"):
        MobilePackageAnalysisBenchmarkFixtureProfile.model_validate(escalated)

    raw_case = profile.cases[0].model_dump(mode="json", by_alias=True)
    raw_aliases = (
        "rawPackageContentEmbedded",
        "rawParserOutputEmbedded",
        "rawManifestEmbedded",
        "signingMaterialEmbedded",
        "rawSecurityConfigurationEmbedded",
        "deviceStateEmbedded",
        "credentialMaterialEmbedded",
        "packagePathEmbedded",
    )
    for value in (True, 0, 1, "false"):
        raw_drift = deepcopy(raw_case)
        raw_drift.update(dict.fromkeys(raw_aliases, value))
        with pytest.raises(ValidationError) as caught:
            MobilePackageAnalysisBenchmarkFixtureCase.model_validate(raw_drift)
        assert set(raw_aliases).issubset({str(error["loc"][0]) for error in caught.value.errors()})

    zero_aliases = (
        "packageWriteOperations",
        "networkRequests",
        "dnsRequests",
        "emulatorSessions",
        "deviceSessions",
        "packageInstallations",
        "applicationLaunches",
        "instrumentationSessions",
        "dynamicTargetExecutions",
        "debuggerAttaches",
        "storageReads",
        "tlsConnections",
        "authenticationInvocations",
        "credentialReads",
        "hostFilesystemReads",
    )
    for value in (True, 1, "0"):
        counter_drift = deepcopy(raw_case)
        counter_drift.update(dict.fromkeys(zero_aliases, value))
        with pytest.raises(ValidationError) as caught:
            MobilePackageAnalysisBenchmarkFixtureCase.model_validate(counter_drift)
        assert set(zero_aliases).issubset({str(error["loc"][0]) for error in caught.value.errors()})


@pytest.mark.asyncio
async def test_contextful_wire_loader_rechecks_graph_evidence_and_external_anchor(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, admission, reanalysis = await _admitted_pair(tmp_path, sample_campaign)
    validation = bind_mobile_package_analysis_reanalysis(
        source.source_inputs,
        admission,
        reanalysis.source_inputs,
        source_graph_store=source.graph_store,
        reanalysis_graph_store=reanalysis.graph_store,
        trust_anchor=source.trust_anchor,
    )
    wire = validation.model_dump(mode="json", by_alias=True)

    assert (
        load_verified_mobile_package_analysis_reanalysis_validation(
            wire,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )
        == validation
    )

    forged_graph = deepcopy(wire)
    forged_graph["validationId"] = ""
    forged_graph["validationDigest"] = ""
    forged_graph["sourceAdmission"]["admissionId"] = ""
    forged_graph["sourceAdmission"]["admissionDigest"] = ""
    forged_event = forged_graph["sourceAdmission"]["observationGraphEvent"]
    forged_event["eventId"] = ""
    forged_event["eventDigest"] = ""
    forged_event["occurredAt"] = "2026-08-27T15:59:59Z"
    canonical_forged_event = type(admission.observation_graph_event).model_validate(forged_event)
    forged_hypothesis_event = forged_graph["sourceAdmission"]["hypothesisGraphEvent"]
    assert forged_hypothesis_event is not None
    forged_hypothesis_event["eventId"] = ""
    forged_hypothesis_event["eventDigest"] = ""
    forged_hypothesis_event["previousEventDigest"] = canonical_forged_event.event_digest
    forged_graph_model = MobilePackageAnalysisReanalysisValidation.model_validate(forged_graph)
    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        load_verified_mobile_package_analysis_reanalysis_validation(
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
    execution["sourceRootDigest"] = mobile_package_analysis_source_root_digest(
        attestation_sha256=execution["attestationSha256"],
        result_receipt_sha256=execution["resultReceiptSha256"],
        trust_anchor_digest=execution["verification"]["trustAnchorDigest"],
        statement_sha256=execution["verification"]["statementSha256"],
    )
    forged_attestation_model = MobilePackageAnalysisReanalysisValidation.model_validate(
        forged_attestation
    )
    with pytest.raises(
        MobilePackageAnalysisReanalysisBenchmarkError,
        match="wire re-verification failed closed",
    ):
        load_verified_mobile_package_analysis_reanalysis_validation(
            forged_attestation_model,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=source.trust_anchor,
        )

    foreign_anchor_payload = source.trust_anchor.model_dump(mode="json", by_alias=True)
    foreign_anchor_payload["keys"][0]["publicKeyBase64url"] = (
        mobile_package_analysis_execution_public_key(
            sha256(b"MOBILE-001D foreign deployment trust anchor").digest()
        )
    )
    foreign_anchor = MobilePackageAnalysisExecutionTrustAnchor.model_validate(
        foreign_anchor_payload
    )
    with pytest.raises(MobilePackageAnalysisReanalysisBenchmarkError, match="failed closed"):
        load_verified_mobile_package_analysis_reanalysis_validation(
            wire,
            source.source_inputs,
            reanalysis.source_inputs,
            source_graph_store=source.graph_store,
            reanalysis_graph_store=reanalysis.graph_store,
            trust_anchor=foreign_anchor,
        )
