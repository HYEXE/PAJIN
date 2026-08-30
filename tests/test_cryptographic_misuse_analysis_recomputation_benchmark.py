from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from inspect import getsource
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_cryptographic_misuse_analysis_admission import (
    _SIGNAL_BY_CLASS,
    _Context,
    _context,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainValidationStrategy,
    resolve_registered_domain_benchmark_plan,
)
from pajin.discovery import CryptographySurfaceClass
from pajin.domain.models import CampaignManifest
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow import (
    cryptographic_misuse_analysis_recomputation_benchmark as recomputation_module,
)
from pajin.workflow.cryptographic_misuse_analysis_admission import (
    CryptographicMisuseAnalysisKnowledgeAdmission,
    CryptographicMisuseAnalysisResultDisposition,
    CryptographicMisuseOracleDisposition,
)
from pajin.workflow.cryptographic_misuse_analysis_recomputation_benchmark import (
    CryptographicBenchmarkExpectedOutcome,
    CryptographicBenchmarkGroundTruthClass,
    CryptographicMisuseAnalysisBenchmarkVectorCase,
    CryptographicMisuseAnalysisBenchmarkVectorProfile,
    CryptographicMisuseAnalysisRecomputationBenchmarkError,
    CryptographicMisuseAnalysisRecomputationComparison,
    CryptographicMisuseAnalysisRecomputationValidation,
    bind_cryptographic_misuse_analysis_independent_recomputation,
    load_verified_cryptographic_misuse_analysis_recomputation_validation,
    registered_cryptographic_misuse_analysis_benchmark_vector_profile,
)

_SOURCE_ANALYZER_DIGEST = sha256(b"CRYPTO-001D source analyzer implementation").hexdigest()
_RECOMPUTATION_ANALYZER_DIGEST = sha256(
    b"CRYPTO-001D recomputation analyzer implementation"
).hexdigest()
_SOURCE_IMAGE_DIGEST = sha256(b"CRYPTO-001D source sandbox image").hexdigest()
_RECOMPUTATION_IMAGE_DIGEST = sha256(b"CRYPTO-001D recomputation sandbox image").hexdigest()
_SOURCE_SIGNING_SEED = "crypto-d-source-attestation"
_RECOMPUTATION_SIGNING_SEED = "crypto-d-recomputation-attestation"
_SOURCE_SIGNING_KEY_ID = "cryptographic-analysis.crypto-d-source"
_RECOMPUTATION_SIGNING_KEY_ID = "cryptographic-analysis.crypto-d-recomputation"
_RESULT_BODY = b"bounded-cryptographic-analysis-result"
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)

_PROFILE_TRUE_FIELDS = (
    "seeded_vector_requirements_registered",
    "private_ground_truth_requirements_registered",
    "seeded_vectors_required",
    "sanitized_immutable_vectors_required",
    "disposable_offline_sandbox_required",
    "network_and_dns_disabled_required",
    "non_root_runtime_required",
    "read_only_noexec_artifact_mount_required",
    "positive_controls_registered",
    "negative_controls_registered",
    "evidence_completeness_required",
    "independent_implementation_recomputation_required",
    "domain_worker_profile_required",
)
_CASE_RAW_FALSE_FIELDS = (
    "raw_artifact_content_embedded",
    "raw_result_body_embedded",
    "raw_key_material_embedded",
    "key_reference_embedded",
    "raw_ciphertext_embedded",
    "raw_plaintext_embedded",
    "raw_configuration_embedded",
    "raw_parameter_material_embedded",
    "credential_material_embedded",
)
_CASE_ZERO_FIELDS = (
    "artifact_write_operations",
    "network_requests",
    "dns_queries",
    "key_material_reads",
    "key_reference_reads",
    "key_store_sessions",
    "credential_reads",
    "cryptographic_operations",
    "key_search_attempts",
    "protocol_negotiations",
    "oracle_invocations",
    "plaintext_outputs",
    "key_material_outputs",
    "target_process_executions",
    "shell_commands",
    "debugger_attaches",
    "host_filesystem_reads",
)
_REQUIRED_EVIDENCE = (
    "private-ground-truth-attestation",
    "vector-materialization-attestation",
    "source-execution-attestation",
    "source-non-root-offline-runtime-receipt",
    "source-result-receipt",
    "recomputation-execution-attestation",
    "recomputation-non-root-offline-runtime-receipt",
    "recomputation-result-receipt",
    "cleanup-receipt",
)


@dataclass(frozen=True, slots=True)
class _AdmittedPair:
    source: _Context
    source_admission: CryptographicMisuseAnalysisKnowledgeAdmission
    recomputation: _Context


def _token(value: str) -> str:
    return value.replace("-", "_").replace(":", "_")


async def _source_context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: CryptographySurfaceClass = CryptographySurfaceClass.PROTOCOL,
    result_disposition: CryptographicMisuseAnalysisResultDisposition = (
        CryptographicMisuseAnalysisResultDisposition.REVIEW
    ),
    result_body: bytes = _RESULT_BODY,
    result_size: int = 4_096,
) -> _Context:
    token = _token(surface_class.value)
    return await _context(
        tmp_path / "source",
        sample_campaign,
        surface_class=surface_class,
        result_disposition=result_disposition,
        result_body=result_body,
        result_size=result_size,
        run_id=f"run_20260828T120000Z_crypto_d_source_{token}",
        request_id=f"tool_crypto_d_source_{token}",
        execution_id=f"cryptographic-execution:crypto-d-source-{token}",
        signing_seed=_SOURCE_SIGNING_SEED,
        signing_key_id=_SOURCE_SIGNING_KEY_ID,
        analyzer_executable_sha256=_SOURCE_ANALYZER_DIGEST,
        sandbox_image_sha256=_SOURCE_IMAGE_DIGEST,
        evidence_directory_label="external-cryptographic-source-d",
    )


async def _recomputation_context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    label: str,
    surface_class: CryptographySurfaceClass = CryptographySurfaceClass.PROTOCOL,
    result_disposition: CryptographicMisuseAnalysisResultDisposition = (
        CryptographicMisuseAnalysisResultDisposition.REVIEW
    ),
    result_body: bytes = _RESULT_BODY,
    result_size: int = 4_096,
    execution_offset: timedelta = timedelta(seconds=20),
    signing_seed: str = _RECOMPUTATION_SIGNING_SEED,
    signing_key_id: str = _RECOMPUTATION_SIGNING_KEY_ID,
    analyzer_executable_sha256: str = _RECOMPUTATION_ANALYZER_DIGEST,
    sandbox_image_sha256: str = _RECOMPUTATION_IMAGE_DIGEST,
) -> _Context:
    token = _token(f"{surface_class.value}_{label}")
    return await _context(
        tmp_path / label,
        sample_campaign,
        surface_class=surface_class,
        result_disposition=result_disposition,
        result_body=result_body,
        result_size=result_size,
        run_id=f"run_20260828T120100Z_crypto_d_{token}",
        request_id=f"tool_crypto_d_{token}",
        execution_id=f"cryptographic-execution:crypto-d-{token}",
        execution_offset=execution_offset,
        signing_seed=signing_seed,
        signing_key_id=signing_key_id,
        analyzer_executable_sha256=analyzer_executable_sha256,
        sandbox_image_sha256=sandbox_image_sha256,
        evidence_directory_label=f"external-cryptographic-{token}",
    )


async def _admitted_pair(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: CryptographySurfaceClass = CryptographySurfaceClass.PROTOCOL,
    source_disposition: CryptographicMisuseAnalysisResultDisposition = (
        CryptographicMisuseAnalysisResultDisposition.REVIEW
    ),
    recomputation_disposition: CryptographicMisuseAnalysisResultDisposition = (
        CryptographicMisuseAnalysisResultDisposition.REVIEW
    ),
    source_body: bytes = _RESULT_BODY,
    recomputation_body: bytes = _RESULT_BODY,
    source_size: int = 4_096,
    recomputation_size: int = 4_096,
    recomputation_offset: timedelta = timedelta(seconds=20),
) -> _AdmittedPair:
    source = await _source_context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        result_disposition=source_disposition,
        result_body=source_body,
        result_size=source_size,
    )
    candidate = source.gate.prepare_candidate(source.source_inputs, source.graph_binding)
    admission = source.gate.admit(source.source_inputs, candidate)
    recomputation = await _recomputation_context(
        tmp_path,
        sample_campaign,
        label="recomputation",
        surface_class=surface_class,
        result_disposition=recomputation_disposition,
        result_body=recomputation_body,
        result_size=recomputation_size,
        execution_offset=recomputation_offset,
    )
    return _AdmittedPair(
        source=source,
        source_admission=admission,
        recomputation=recomputation,
    )


def _bind(pair: _AdmittedPair) -> CryptographicMisuseAnalysisRecomputationValidation:
    return bind_cryptographic_misuse_analysis_independent_recomputation(
        pair.source.source_inputs,
        pair.source_admission,
        pair.recomputation.source_inputs,
        source_graph_store=pair.source.graph_store,
        recomputation_graph_store=pair.recomputation.graph_store,
        source_trust_anchor=pair.source.trust_anchor,
        recomputation_trust_anchor=pair.recomputation.trust_anchor,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_class", tuple(CryptographySurfaceClass))
async def test_all_four_surfaces_match_with_distinct_implementation_coordinates_and_no_graph_writes(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: CryptographySurfaceClass,
) -> None:
    pair = await _admitted_pair(tmp_path, sample_campaign, surface_class=surface_class)
    source_events = len(pair.source.graph_store.event_log.events())
    recomputation_events = len(pair.recomputation.graph_store.event_log.events())

    validation = _bind(pair)

    assert validation.comparison is CryptographicMisuseAnalysisRecomputationComparison.MATCHED
    assert validation.state == "independent-recomputation-match"
    assert validation.result_body_digest_matched is True
    assert validation.result_bytes_matched is True
    assert validation.result_disposition_matched is True
    assert validation.oracle_disposition_matched is True
    assert validation.review_signal_matched is True
    assert (
        validation.source_execution.oracle_verdict.review_signal is _SIGNAL_BY_CLASS[surface_class]
    )
    assert (
        validation.recomputation_execution.oracle_verdict.review_signal
        is _SIGNAL_BY_CLASS[surface_class]
    )
    assert (
        validation.source_execution.preparation.sandbox.analyzer_executable_sha256
        != validation.recomputation_execution.preparation.sandbox.analyzer_executable_sha256
    )
    assert (
        validation.source_execution.preparation.sandbox.sandbox_image_sha256
        != validation.recomputation_execution.preparation.sandbox.sandbox_image_sha256
    )
    assert validation.source_execution.trust_anchor != (
        validation.recomputation_execution.trust_anchor
    )
    assert validation.signed_timestamp_order_verified is True
    assert validation.distinct_implementation_coordinates_verified is True
    assert validation.source_bound_recomputation_authorization_verified is False
    assert validation.cross_signer_clock_synchronization_verified is False
    assert validation.self_authenticating_projection is False
    assert validation.source_code_independence_verified is False
    assert validation.algorithm_independence_verified is False
    assert validation.organization_independence_verified is False
    assert validation.host_independence_verified is False
    assert validation.common_mode_failure_excluded is False
    assert validation.semantic_misuse_truth_established is False
    assert validation.finding_authority is False
    assert validation.execution_authorized is False
    assert len(pair.source.graph_store.event_log.events()) == source_events
    assert len(pair.recomputation.graph_store.event_log.events()) == recomputation_events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "recomputation_disposition", "recomputation_body", "expected"),
    (
        (
            "changed-disposition",
            CryptographicMisuseAnalysisResultDisposition.NO_SIGNAL,
            _RESULT_BODY,
            CryptographicMisuseAnalysisRecomputationComparison.CHANGED,
        ),
        (
            "different-body",
            CryptographicMisuseAnalysisResultDisposition.REVIEW,
            b"different-bounded-cryptographic-analysis-result",
            CryptographicMisuseAnalysisRecomputationComparison.UNRESOLVED,
        ),
    ),
)
async def test_changed_and_unresolved_comparisons_remain_bounded(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    label: str,
    recomputation_disposition: CryptographicMisuseAnalysisResultDisposition,
    recomputation_body: bytes,
    expected: CryptographicMisuseAnalysisRecomputationComparison,
) -> None:
    pair = await _admitted_pair(
        tmp_path / label,
        sample_campaign,
        recomputation_disposition=recomputation_disposition,
        recomputation_body=recomputation_body,
    )

    validation = _bind(pair)

    assert validation.comparison is expected
    assert validation.semantic_misuse_truth_established is False
    assert validation.negative_security_claim_established is False
    if expected is CryptographicMisuseAnalysisRecomputationComparison.CHANGED:
        assert validation.result_body_digest_matched is True
        assert validation.result_disposition_matched is False
        assert validation.oracle_disposition_matched is False
        assert validation.review_signal_matched is False
    else:
        assert validation.result_body_digest_matched is False
        assert validation.result_disposition_matched is True
        assert validation.oracle_disposition_matched is True
        assert validation.review_signal_matched is True


@pytest.mark.asyncio
async def test_equal_result_digest_with_different_signed_bytes_fails_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    pair = await _admitted_pair(
        tmp_path,
        sample_campaign,
        source_size=4_096,
        recomputation_size=4_097,
    )

    with pytest.raises(
        CryptographicMisuseAnalysisRecomputationBenchmarkError,
        match="failed closed",
    ):
        _bind(pair)


@pytest.mark.asyncio
async def test_reused_implementation_anchor_or_signer_provenance_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _source_context(tmp_path / "base", sample_campaign)
    candidate = source.gate.prepare_candidate(source.source_inputs, source.graph_binding)
    admission = source.gate.admit(source.source_inputs, candidate)
    source_event_count = len(source.graph_store.event_log.events())
    variants = (
        (
            "executable",
            _SOURCE_ANALYZER_DIGEST,
            _RECOMPUTATION_IMAGE_DIGEST,
            _RECOMPUTATION_SIGNING_SEED,
            _RECOMPUTATION_SIGNING_KEY_ID,
        ),
        (
            "image",
            _RECOMPUTATION_ANALYZER_DIGEST,
            _SOURCE_IMAGE_DIGEST,
            _RECOMPUTATION_SIGNING_SEED,
            _RECOMPUTATION_SIGNING_KEY_ID,
        ),
        (
            "sandbox",
            _SOURCE_ANALYZER_DIGEST,
            _SOURCE_IMAGE_DIGEST,
            _RECOMPUTATION_SIGNING_SEED,
            _RECOMPUTATION_SIGNING_KEY_ID,
        ),
        (
            "anchor",
            _SOURCE_ANALYZER_DIGEST,
            _SOURCE_IMAGE_DIGEST,
            _SOURCE_SIGNING_SEED,
            _SOURCE_SIGNING_KEY_ID,
        ),
        (
            "signer",
            _RECOMPUTATION_ANALYZER_DIGEST,
            _RECOMPUTATION_IMAGE_DIGEST,
            _SOURCE_SIGNING_SEED,
            _SOURCE_SIGNING_KEY_ID,
        ),
    )
    for label, analyzer_digest, image_digest, signing_seed, signing_key_id in variants:
        recomputation = await _recomputation_context(
            tmp_path / label,
            sample_campaign,
            label=label,
            analyzer_executable_sha256=analyzer_digest,
            sandbox_image_sha256=image_digest,
            signing_seed=signing_seed,
            signing_key_id=signing_key_id,
        )
        recomputation_event_count = len(recomputation.graph_store.event_log.events())
        with pytest.raises(
            CryptographicMisuseAnalysisRecomputationBenchmarkError,
            match="failed closed",
        ):
            bind_cryptographic_misuse_analysis_independent_recomputation(
                source.source_inputs,
                admission,
                recomputation.source_inputs,
                source_graph_store=source.graph_store,
                recomputation_graph_store=recomputation.graph_store,
                source_trust_anchor=source.trust_anchor,
                recomputation_trust_anchor=recomputation.trust_anchor,
            )
        assert len(source.graph_store.event_log.events()) == source_event_count
        assert len(recomputation.graph_store.event_log.events()) == recomputation_event_count


@pytest.mark.asyncio
async def test_every_execution_identity_is_distinct_and_invalid_signed_timestamp_order_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = await _admitted_pair(tmp_path / "valid", sample_campaign)
    validation = _bind(pair)
    expected_coordinates = {
        "preparationId",
        "preparationDigest",
        "runId",
        "sourceRootDigest",
        "requestId",
        "requestDigest",
        "normalizedParametersDigest",
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
        "trustAnchorDigest",
        "activeSignerKeyId",
        "activeSignerPublicKey",
        "sandboxBindingId",
        "sandboxBindingDigest",
        "analyzerExecutableSHA256",
        "sandboxImageSHA256",
        "executionId",
        "gatewayOutcomeDigest",
        "statementSha256",
        "sandboxRuntimeReceiptId",
        "sandboxRuntimeReceiptDigest",
        "attestationSha256",
        "resultReceiptId",
        "resultReceiptDigest",
        "resultReceiptSha256",
        "oracleVerdictId",
        "oracleVerdictDigest",
    }
    source_coordinates = recomputation_module._execution_identity_coordinates(
        validation.source_execution
    )
    recomputation_coordinates = recomputation_module._execution_identity_coordinates(
        validation.recomputation_execution
    )
    assert set(source_coordinates) == expected_coordinates
    assert set(recomputation_coordinates) == expected_coordinates
    assert all(
        source_coordinates[name] != recomputation_coordinates[name] for name in expected_coordinates
    )

    real_coordinates = recomputation_module._execution_identity_coordinates
    for coordinate in expected_coordinates:
        collided = dict(recomputation_coordinates)
        collided[coordinate] = source_coordinates[coordinate]
        calls = iter((source_coordinates, collided))
        monkeypatch.setattr(
            recomputation_module,
            "_execution_identity_coordinates",
            lambda _execution, values=calls: next(values),
        )
        with pytest.raises(ValueError, match=rf"reused.*{coordinate}"):
            recomputation_module._require_distinct_recomputation_provenance(
                validation.source_execution,
                validation.recomputation_execution,
            )
    monkeypatch.setattr(
        recomputation_module,
        "_execution_identity_coordinates",
        real_coordinates,
    )

    invalid_timestamp_order = await _recomputation_context(
        tmp_path / "invalid-timestamp-order",
        sample_campaign,
        label="invalid-timestamp-order",
        execution_offset=timedelta(),
    )
    with pytest.raises(
        CryptographicMisuseAnalysisRecomputationBenchmarkError,
        match="failed closed",
    ):
        bind_cryptographic_misuse_analysis_independent_recomputation(
            pair.source.source_inputs,
            pair.source_admission,
            invalid_timestamp_order.source_inputs,
            source_graph_store=pair.source.graph_store,
            recomputation_graph_store=invalid_timestamp_order.graph_store,
            source_trust_anchor=pair.source.trust_anchor,
            recomputation_trust_anchor=invalid_timestamp_order.trust_anchor,
        )


@pytest.mark.asyncio
async def test_source_admission_must_be_stored_in_the_exact_source_graph(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    pair = await _admitted_pair(tmp_path / "pair", sample_campaign)
    foreign = await _source_context(
        tmp_path / "foreign",
        sample_campaign,
        surface_class=CryptographySurfaceClass.CIPHERTEXT,
    )
    foreign_candidate = foreign.gate.prepare_candidate(
        foreign.source_inputs,
        foreign.graph_binding,
    )
    foreign_admission = foreign.gate.admit(foreign.source_inputs, foreign_candidate)
    source_events = len(pair.source.graph_store.event_log.events())
    recomputation_events = len(pair.recomputation.graph_store.event_log.events())

    with pytest.raises(
        CryptographicMisuseAnalysisRecomputationBenchmarkError,
        match="failed closed",
    ):
        bind_cryptographic_misuse_analysis_independent_recomputation(
            pair.source.source_inputs,
            foreign_admission,
            pair.recomputation.source_inputs,
            source_graph_store=pair.source.graph_store,
            recomputation_graph_store=pair.recomputation.graph_store,
            source_trust_anchor=pair.source.trust_anchor,
            recomputation_trust_anchor=pair.recomputation.trust_anchor,
        )

    assert len(pair.source.graph_store.event_log.events()) == source_events
    assert len(pair.recomputation.graph_store.event_log.events()) == recomputation_events


@pytest.mark.asyncio
async def test_source_and_recomputation_must_use_distinct_graph_stores(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    pair = await _admitted_pair(tmp_path, sample_campaign)
    source_events = len(pair.source.graph_store.event_log.events())
    recomputation_events = len(pair.recomputation.graph_store.event_log.events())

    with pytest.raises(
        CryptographicMisuseAnalysisRecomputationBenchmarkError,
        match="failed closed",
    ):
        bind_cryptographic_misuse_analysis_independent_recomputation(
            pair.source.source_inputs,
            pair.source_admission,
            pair.recomputation.source_inputs,
            source_graph_store=pair.source.graph_store,
            recomputation_graph_store=pair.source.graph_store,
            source_trust_anchor=pair.source.trust_anchor,
            recomputation_trust_anchor=pair.recomputation.trust_anchor,
        )

    assert len(pair.source.graph_store.event_log.events()) == source_events
    assert len(pair.recomputation.graph_store.event_log.events()) == recomputation_events


@pytest.mark.asyncio
async def test_contextful_wire_loader_rechecks_graph_evidence_and_rejects_forged_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    pair = await _admitted_pair(tmp_path, sample_campaign)
    validation = _bind(pair)
    wire = validation.model_dump(mode="json", by_alias=True)
    source_events = len(pair.source.graph_store.event_log.events())
    recomputation_events = len(pair.recomputation.graph_store.event_log.events())

    bare = CryptographicMisuseAnalysisRecomputationValidation.model_validate(wire)
    assert bare == validation
    assert (
        load_verified_cryptographic_misuse_analysis_recomputation_validation(
            wire,
            pair.source.source_inputs,
            pair.recomputation.source_inputs,
            source_graph_store=pair.source.graph_store,
            recomputation_graph_store=pair.recomputation.graph_store,
            source_trust_anchor=pair.source.trust_anchor,
            recomputation_trust_anchor=pair.recomputation.trust_anchor,
        )
        == validation
    )

    forged_graph = deepcopy(wire)
    forged_graph["validationId"] = ""
    forged_graph["validationDigest"] = ""
    forged_graph["sourceAdmission"]["admissionId"] = ""
    forged_graph["sourceAdmission"]["admissionDigest"] = ""
    observation = forged_graph["sourceAdmission"]["observationGraphEvent"]
    observation["eventId"] = ""
    observation["eventDigest"] = ""
    observation["occurredAt"] = (NOW + timedelta(seconds=21)).isoformat()
    canonical_observation = type(pair.source_admission.observation_graph_event).model_validate(
        observation
    )
    hypothesis = forged_graph["sourceAdmission"]["hypothesisGraphEvent"]
    assert hypothesis is not None
    hypothesis["eventId"] = ""
    hypothesis["eventDigest"] = ""
    hypothesis["previousEventDigest"] = canonical_observation.event_digest
    forged_model = CryptographicMisuseAnalysisRecomputationValidation.model_validate(forged_graph)
    with pytest.raises(
        CryptographicMisuseAnalysisRecomputationBenchmarkError,
        match="failed closed",
    ):
        load_verified_cryptographic_misuse_analysis_recomputation_validation(
            forged_model,
            pair.source.source_inputs,
            pair.recomputation.source_inputs,
            source_graph_store=pair.source.graph_store,
            recomputation_graph_store=pair.recomputation.graph_store,
            source_trust_anchor=pair.source.trust_anchor,
            recomputation_trust_anchor=pair.recomputation.trust_anchor,
        )

    coerced = deepcopy(wire)
    coerced["validationId"] = ""
    coerced["validationDigest"] = ""
    coerced["resultBodyDigestMatched"] = 1
    with pytest.raises(ValidationError, match="comparison markers"):
        CryptographicMisuseAnalysisRecomputationValidation.model_validate(coerced)

    escalated = deepcopy(wire)
    escalated["validationId"] = ""
    escalated["validationDigest"] = ""
    escalated["executionAuthorized"] = 1
    with pytest.raises(ValidationError, match="cannot grant authority"):
        CryptographicMisuseAnalysisRecomputationValidation.model_validate(escalated)

    unknown = validation.model_copy(deep=True)
    object.__setattr__(
        unknown.recomputation_execution.oracle_verdict,
        "unmodeledAuthority",
        True,
    )
    with pytest.raises(
        CryptographicMisuseAnalysisRecomputationBenchmarkError,
        match="failed closed",
    ):
        load_verified_cryptographic_misuse_analysis_recomputation_validation(
            unknown,
            pair.source.source_inputs,
            pair.recomputation.source_inputs,
            source_graph_store=pair.source.graph_store,
            recomputation_graph_store=pair.recomputation.graph_store,
            source_trust_anchor=pair.source.trust_anchor,
            recomputation_trust_anchor=pair.recomputation.trust_anchor,
        )

    assert len(pair.source.graph_store.event_log.events()) == source_events
    assert len(pair.recomputation.graph_store.event_log.events()) == recomputation_events


def test_source_imports_exclude_source_oracle_runtime_and_measurement_authority() -> None:
    tree = ast.parse(getsource(recomputation_module))
    imported_modules: set[str] = set()
    directly_imported_modules: set[str] = set()
    imported_names: set[str] = set()
    imported_from: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = {alias.name for alias in node.names}
            imported_modules.update(modules)
            directly_imported_modules.update(modules)
            imported_names.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
            imported_names.update(alias.asname for alias in node.names if alias.asname)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = {alias.name for alias in node.names}
            imported_modules.add(module)
            imported_names.update(names)
            imported_names.update(alias.asname for alias in node.names if alias.asname)
            imported_from.setdefault(module, set()).update(names)

    forbidden_module_prefixes = (
        "aiohttp",
        "docker",
        "httpx",
        "kubernetes",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "tarfile",
        "urllib",
        "zipfile",
        "pajin.benchmark.deterministic_baseline",
        "pajin.benchmark.measurement",
        "pajin.benchmark.redteam",
        "pajin.benchmark.scanner_measurement",
        "pajin.benchmark.single_agent_measurement",
        "pajin.capabilities.existing",
        "pajin.controls.materializer",
        "pajin.graph.admission",
        "pajin.graph.projection",
        "pajin.modes.ctf",
        "pajin.replay.materializer",
        "pajin.runtime.safe_files",
        "pajin.runtime.secrets",
        "pajin.runtime.worker",
        "pajin.tools",
    )
    assert not any(
        module == prefix or module.startswith(f"{prefix}.")
        for module in imported_modules
        for prefix in forbidden_module_prefixes
    )

    sensitive_modules = {
        "pajin.capabilities.cryptographic_misuse_analysis": {
            "CryptographicAnalysisInputKind",
            "CryptographicMisuseAnalysisOperation",
            "CryptographicMisuseAnalysisPreparation",
            "CryptographicMisuseAnalysisRequest",
            "CryptographicMisuseAnalysisSandboxBinding",
            "CryptographicMisuseAnalyzer",
            "CryptographicMisuseRuleSetRef",
            "CryptographicMisuseSignalKind",
            "CryptographicSurfaceAnalysisMapping",
            "registered_cryptographic_misuse_rule_set",
        },
        "pajin.workflow.cryptographic_misuse_analysis_admission": {
            "CryptographicMisuseAnalysisExecutionBundle",
            "CryptographicMisuseAnalysisExecutionKeyState",
            "CryptographicMisuseAnalysisExecutionTrustAnchor",
            "CryptographicMisuseAnalysisExecutionVerification",
            "CryptographicMisuseAnalysisExecutionVerificationKey",
            "CryptographicMisuseAnalysisKnowledgeAdmission",
            "CryptographicMisuseAnalysisObservationSourceInputs",
            "CryptographicMisuseAnalysisOracleVerdict",
            "CryptographicMisuseAnalysisResultDisposition",
            "CryptographicMisuseAnalysisResultReceipt",
            "CryptographicMisuseAnalysisSandboxRuntimeReceipt",
            "CryptographicMisuseOracleDisposition",
            "VerifiedCryptographicMisuseAnalysisObservationSource",
            "cryptographic_misuse_analysis_source_root_digest",
            "load_verified_cryptographic_misuse_analysis_observation_source",
            "registered_cryptographic_misuse_analysis_oracle_policy",
            "verify_cryptographic_misuse_analysis_execution_bundle",
        },
    }
    assert directly_imported_modules.isdisjoint(sensitive_modules)
    assert all(
        imported_from.get(module, set()) <= allowed_names
        for module, allowed_names in sensitive_modules.items()
    )
    assert imported_names.isdisjoint(
        {
            "*",
            "CTFCryptoXORTool",
            "CryptographicMisuseAnalysisExecutionAttestor",
            "CryptographicMisuseAnalysisKnowledgeAdmissionGate",
            "CryptographicMisuseAnalysisTool",
            "DockerWorkerBackend",
            "GraphAdmissionAuthority",
            "GraphProjectionCoordinator",
            "ReplaySessionMaterializer",
            "SecretBroker",
            "_CryptographicMisuseAnalysisExecutorAdapter",
            "_CryptographicMisuseAnalysisMaterializer",
            "_CryptographicMisuseAnalysisSuccessOracle",
            "_solve_single_byte_xor",
            "aggregate_walking_benchmark_metrics",
            "cryptographic_misuse_analysis",
            "cryptographic_misuse_analysis_admission",
            "prepare_cryptographic_misuse_analysis",
            "recompute_cryptographic_misuse_analysis_oracle_verdict",
        }
    )


def test_seeded_vector_profile_registers_exact_unmeasured_crypto_requirements() -> None:
    profile = registered_cryptographic_misuse_analysis_benchmark_vector_profile()
    plan = resolve_registered_domain_benchmark_plan(profile.domain_benchmark_plan)

    assert profile.state == "registered-seeded-vector-requirements-not-materialized-or-measured"
    assert profile.covered_surface_classes == tuple(CryptographySurfaceClass)
    assert len(profile.cases) == 8
    assert [case.vector_id for case in profile.cases] == sorted(
        case.vector_id for case in profile.cases
    )
    assert plan.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    assert plan.validation_strategy is DomainValidationStrategy.INDEPENDENT_RECOMPUTATION
    crypto_requirements = tuple(
        requirement
        for requirement in plan.metric_requirements
        if requirement.metric.metric_id.startswith("cryptography.")
    )
    assert {item.metric.metric_id for item in crypto_requirements} == {
        "cryptography.test-vector-coverage",
        "cryptography.independent-recomputation-success-rate",
    }
    assert all(
        item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
        for item in crypto_requirements
    )

    for surface_class in CryptographySurfaceClass:
        cases = tuple(case for case in profile.cases if case.surface_class is surface_class)
        assert len(cases) == 2
        positive = next(
            case
            for case in cases
            if case.ground_truth_class is CryptographicBenchmarkGroundTruthClass.KNOWN_POSITIVE
        )
        negative = next(
            case
            for case in cases
            if case.ground_truth_class is CryptographicBenchmarkGroundTruthClass.NEGATIVE_CONTROL
        )
        assert positive.expected_outcome is CryptographicBenchmarkExpectedOutcome.REVIEW_SIGNAL
        assert positive.expected_result_disposition is (
            CryptographicMisuseAnalysisResultDisposition.REVIEW
        )
        assert positive.expected_oracle_disposition is (
            CryptographicMisuseOracleDisposition.STRUCTURALLY_CONSISTENT_REVIEW
        )
        assert positive.expected_review_signal is _SIGNAL_BY_CLASS[surface_class]
        assert negative.expected_outcome is (CryptographicBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL)
        assert negative.expected_result_disposition is (
            CryptographicMisuseAnalysisResultDisposition.NO_SIGNAL
        )
        assert negative.expected_oracle_disposition is (
            CryptographicMisuseOracleDisposition.INCONCLUSIVE_NO_SIGNAL
        )
        assert negative.expected_review_signal is None
        assert positive.required_evidence == negative.required_evidence == _REQUIRED_EVIDENCE
        assert positive.synthetic_test_only_required is True
        assert negative.synthetic_test_only_required is True

    profile_booleans = {
        name: getattr(profile, name)
        for name in type(profile).model_fields
        if type(getattr(profile, name)) is bool
    }
    assert {name for name, value in profile_booleans.items() if value} == set(_PROFILE_TRUE_FIELDS)
    assert all(
        value is False
        for name, value in profile_booleans.items()
        if name not in _PROFILE_TRUE_FIELDS
    )
    for case in profile.cases:
        assert all(getattr(case, name) is False for name in _CASE_RAW_FALSE_FIELDS)
        assert all(
            type(getattr(case, name)) is int and getattr(case, name) == 0
            for name in _CASE_ZERO_FIELDS
        )
    assert (
        CryptographicMisuseAnalysisBenchmarkVectorProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        == profile
    )


def test_vector_models_reject_coercion_and_registered_profiles_are_cache_isolated() -> None:
    first = registered_cryptographic_misuse_analysis_benchmark_vector_profile()
    second = registered_cryptographic_misuse_analysis_benchmark_vector_profile()
    assert first == second
    assert first is not second
    assert first.cases[0] is not second.cases[0]
    assert first.cases[0].rule_set is not second.cases[0].rule_set
    assert (
        first.cases[0].rule_set.surface_analysis_mapping[0]
        is not (second.cases[0].rule_set.surface_analysis_mapping[0])
    )

    profile_payload = deepcopy(first.model_dump(mode="json", by_alias=True))
    profile_payload["profileId"] = ""
    profile_payload["profileDigest"] = ""
    profile_payload["executionAuthorized"] = 1
    with pytest.raises(ValidationError, match="cannot claim authority"):
        CryptographicMisuseAnalysisBenchmarkVectorProfile.model_validate(profile_payload)

    raw_case = first.cases[0].model_dump(mode="json", by_alias=True)
    raw_alias_list: list[str] = []
    for name in _CASE_RAW_FALSE_FIELDS:
        alias = CryptographicMisuseAnalysisBenchmarkVectorCase.model_fields[name].alias
        assert alias is not None
        raw_alias_list.append(alias)
    raw_aliases: tuple[str, ...] = tuple(raw_alias_list)
    for invalid in (True, 0, 1, "false"):
        changed = deepcopy(raw_case)
        changed.update(dict.fromkeys(raw_aliases, invalid))
        with pytest.raises(ValidationError) as caught:
            CryptographicMisuseAnalysisBenchmarkVectorCase.model_validate(changed)
        assert set(raw_aliases).issubset({str(error["loc"][0]) for error in caught.value.errors()})

    zero_alias_list: list[str] = []
    for name in _CASE_ZERO_FIELDS:
        alias = CryptographicMisuseAnalysisBenchmarkVectorCase.model_fields[name].alias
        assert alias is not None
        zero_alias_list.append(alias)
    zero_aliases: tuple[str, ...] = tuple(zero_alias_list)
    for invalid in (True, 1, "0"):
        changed = deepcopy(raw_case)
        changed.update(dict.fromkeys(zero_aliases, invalid))
        with pytest.raises(ValidationError) as caught:
            CryptographicMisuseAnalysisBenchmarkVectorCase.model_validate(changed)
        assert set(zero_aliases).issubset({str(error["loc"][0]) for error in caught.value.errors()})

    synthetic_alias = CryptographicMisuseAnalysisBenchmarkVectorCase.model_fields[
        "synthetic_test_only_required"
    ].alias
    assert synthetic_alias is not None
    for invalid in (False, 0, 1, "true"):
        changed = deepcopy(raw_case)
        changed[synthetic_alias] = invalid
        with pytest.raises(ValidationError, match="synthetic test-only"):
            CryptographicMisuseAnalysisBenchmarkVectorCase.model_validate(changed)

    replacement = next(
        outcome
        for outcome in CryptographicBenchmarkExpectedOutcome
        if outcome is not first.cases[0].expected_outcome
    )
    object.__setattr__(first.cases[0], "expected_outcome", replacement)
    assert registered_cryptographic_misuse_analysis_benchmark_vector_profile() == second
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisBenchmarkVectorProfile.model_validate(first)

    unknown = second.model_copy(deep=True)
    object.__setattr__(
        unknown.cases[0].rule_set.surface_analysis_mapping[0],
        "unmodeledAuthority",
        True,
    )
    with pytest.raises(ValidationError, match="unmodeled instance state"):
        CryptographicMisuseAnalysisBenchmarkVectorProfile.model_validate(unknown)
    assert registered_cryptographic_misuse_analysis_benchmark_vector_profile() == second
