from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from inspect import getsource
from pathlib import Path
from typing import Literal, get_args, get_origin

import pytest
from pydantic import BaseModel, ValidationError
from test_forensic_evidence_analysis import (
    _INPUT_KIND_BY_CLASS,
    _OPERATION_BY_CLASS,
    PARSER_CONFIGURATION_DIGEST,
    PARSER_EXECUTABLE_DIGEST,
    SANDBOX_IMAGE_DIGEST,
)
from test_forensic_evidence_analysis_admission import (
    _SIGNAL_BY_CLASS,
    _Context,
    _context,
    _context_source_root,
)

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainValidationStrategy,
    resolve_registered_domain_benchmark_plan,
)
from pajin.discovery import ForensicSurfaceClass
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.workflow import forensic_evidence_analysis_replay_benchmark as replay_module
from pajin.workflow.forensic_evidence_analysis_admission import (
    ForensicEvidenceAnalysisExecutionTrustAnchor,
    ForensicEvidenceAnalysisKnowledgeAdmission,
    ForensicEvidenceAnalysisOracleDisposition,
    ForensicEvidenceAnalysisResultDisposition,
    ForensicEvidenceSourceMembershipTrustAnchor,
    forensic_evidence_analysis_execution_public_key,
    forensic_evidence_source_membership_public_key,
)

_INDEPENDENT_PARSER_EXECUTABLE_DIGEST = sha256(
    b"FORENSICS-001D independent parser executable"
).hexdigest()
_INDEPENDENT_PARSER_CONFIGURATION_DIGEST = sha256(
    b"FORENSICS-001D independent parser configuration"
).hexdigest()
_INDEPENDENT_SANDBOX_IMAGE_DIGEST = sha256(b"FORENSICS-001D independent sandbox image").hexdigest()
_INDEPENDENT_EXECUTION_SIGNING_SEED = "forensics-d-independent-execution"
_INDEPENDENT_EXECUTION_KEY_ID = "forensic-analysis.forensics-d-independent"
_RESULT_BODY = b"bounded-forensic-analysis-result"
_FORENSICS_METRIC_IDS = (
    "forensics.artifact-coverage",
    "forensics.parsing-accuracy",
    "forensics.provenance-preservation-rate",
    "forensics.corrupted-input-handling-rate",
)


@dataclass(frozen=True, slots=True)
class _AdmittedSource:
    context: _Context
    admission: ForensicEvidenceAnalysisKnowledgeAdmission


def _token(value: str) -> str:
    return value.replace("-", "_").replace(":", "_")


def _literal_marker_aliases(
    model: type[BaseModel],
    expected: bool,
) -> set[str]:
    aliases: set[str] = set()
    for name, field in model.model_fields.items():
        arguments = get_args(field.annotation)
        if (
            get_origin(field.annotation) is Literal
            and len(arguments) == 1
            and arguments[0] is expected
        ):
            aliases.add(field.alias or name)
    return aliases


def _foreign_source_membership_anchor(
    anchor: ForensicEvidenceSourceMembershipTrustAnchor,
) -> ForensicEvidenceSourceMembershipTrustAnchor:
    payload = anchor.model_dump(mode="json", by_alias=True)
    keys = payload["keys"]
    assert isinstance(keys, list)
    key = keys[0]
    assert isinstance(key, dict)
    key["publicKeyBase64url"] = forensic_evidence_source_membership_public_key(
        sha256(b"FORENSICS-001D foreign source-membership anchor").digest()
    )
    return ForensicEvidenceSourceMembershipTrustAnchor.model_validate(payload)


def _foreign_execution_anchor(
    anchor: ForensicEvidenceAnalysisExecutionTrustAnchor,
) -> ForensicEvidenceAnalysisExecutionTrustAnchor:
    payload = anchor.model_dump(mode="json", by_alias=True)
    keys = payload["keys"]
    assert isinstance(keys, list)
    key = keys[0]
    assert isinstance(key, dict)
    key["publicKeyBase64url"] = forensic_evidence_analysis_execution_public_key(
        sha256(b"FORENSICS-001D foreign execution anchor").digest()
    )
    return ForensicEvidenceAnalysisExecutionTrustAnchor.model_validate(payload)


async def _source_context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: ForensicSurfaceClass = ForensicSurfaceClass.DISK,
    result_disposition: ForensicEvidenceAnalysisResultDisposition = (
        ForensicEvidenceAnalysisResultDisposition.REVIEW
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
        run_id=f"run_20260828T130000Z_forensics_d_source_{token}",
        request_id=f"tool_forensics_d_source_{token}",
        execution_id=f"forensic-execution:forensics-d-source-{token}",
        evidence_directory_label=f"external-forensics-d-source-{token}",
    )


async def _admitted_source(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    surface_class: ForensicSurfaceClass = ForensicSurfaceClass.DISK,
    result_disposition: ForensicEvidenceAnalysisResultDisposition = (
        ForensicEvidenceAnalysisResultDisposition.REVIEW
    ),
    result_body: bytes = _RESULT_BODY,
    result_size: int = 4_096,
) -> _AdmittedSource:
    context = await _source_context(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
        result_disposition=result_disposition,
        result_body=result_body,
        result_size=result_size,
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    return _AdmittedSource(context=context, admission=admission)


async def _replay_context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    label: str,
    independent: bool,
    surface_class: ForensicSurfaceClass = ForensicSurfaceClass.DISK,
    result_disposition: ForensicEvidenceAnalysisResultDisposition = (
        ForensicEvidenceAnalysisResultDisposition.REVIEW
    ),
    result_body: bytes = _RESULT_BODY,
    result_size: int = 4_096,
    execution_offset: timedelta = timedelta(seconds=20),
    parser_executable_sha256: str | None = None,
    parser_configuration_sha256: str | None = None,
    sandbox_image_sha256: str | None = None,
    execution_signing_seed: str | None = None,
    execution_key_id: str | None = None,
) -> _Context:
    token = _token(f"{surface_class.value}_{label}")
    if independent:
        parser_executable_sha256 = parser_executable_sha256 or _INDEPENDENT_PARSER_EXECUTABLE_DIGEST
        parser_configuration_sha256 = (
            parser_configuration_sha256 or _INDEPENDENT_PARSER_CONFIGURATION_DIGEST
        )
        sandbox_image_sha256 = sandbox_image_sha256 or _INDEPENDENT_SANDBOX_IMAGE_DIGEST
        execution_signing_seed = execution_signing_seed or _INDEPENDENT_EXECUTION_SIGNING_SEED
        execution_key_id = execution_key_id or _INDEPENDENT_EXECUTION_KEY_ID
    else:
        parser_executable_sha256 = parser_executable_sha256 or PARSER_EXECUTABLE_DIGEST
        parser_configuration_sha256 = parser_configuration_sha256 or PARSER_CONFIGURATION_DIGEST
        sandbox_image_sha256 = sandbox_image_sha256 or SANDBOX_IMAGE_DIGEST
        execution_signing_seed = execution_signing_seed or "execution-attestation"
        execution_key_id = execution_key_id or "forensic-analysis.execution"
    return await _context(
        tmp_path / label,
        sample_campaign,
        surface_class=surface_class,
        result_disposition=result_disposition,
        result_body=result_body,
        result_size=result_size,
        run_id=f"run_20260828T130100Z_forensics_d_{token}",
        request_id=f"tool_forensics_d_{token}",
        execution_id=f"forensic-execution:forensics-d-{token}",
        execution_offset=execution_offset,
        evidence_directory_label=f"external-forensics-d-{token}",
        parser_executable_sha256=parser_executable_sha256,
        parser_configuration_sha256=parser_configuration_sha256,
        sandbox_image_sha256=sandbox_image_sha256,
        execution_signing_seed=execution_signing_seed,
        execution_key_id=execution_key_id,
    )


def _bind(
    source: _AdmittedSource,
    replay: _Context,
) -> replay_module.ForensicEvidenceAnalysisReplayValidation:
    return replay_module.bind_forensic_evidence_analysis_replay(
        source.context.source_inputs,
        source.admission,
        replay.source_inputs,
        source_root=_context_source_root(source.context),
        replay_root=_context_source_root(replay),
        source_graph_store=source.context.graph_store,
        replay_graph_store=replay.graph_store,
        source_membership_trust_anchor=source.context.source_trust_anchor,
        source_execution_trust_anchor=source.context.execution_trust_anchor,
        replay_execution_trust_anchor=replay.execution_trust_anchor,
    )


def _load(
    value: object,
    source: _AdmittedSource,
    replay: _Context,
    *,
    source_root: Path | None = None,
    replay_root: Path | None = None,
    source_graph_store: SQLiteGraphStore | None = None,
    replay_graph_store: SQLiteGraphStore | None = None,
    source_membership_trust_anchor: ForensicEvidenceSourceMembershipTrustAnchor | None = None,
    source_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor | None = None,
    replay_execution_trust_anchor: ForensicEvidenceAnalysisExecutionTrustAnchor | None = None,
) -> replay_module.ForensicEvidenceAnalysisReplayValidation:
    return replay_module.load_verified_forensic_evidence_analysis_replay_validation(
        value,
        source.context.source_inputs,
        replay.source_inputs,
        source_root=(source_root or _context_source_root(source.context)),
        replay_root=(replay_root or _context_source_root(replay)),
        source_graph_store=(source_graph_store or source.context.graph_store),
        replay_graph_store=(replay_graph_store or replay.graph_store),
        source_membership_trust_anchor=(
            source_membership_trust_anchor or source.context.source_trust_anchor
        ),
        source_execution_trust_anchor=(
            source_execution_trust_anchor or source.context.execution_trust_anchor
        ),
        replay_execution_trust_anchor=(
            replay_execution_trust_anchor or replay.execution_trust_anchor
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("surface_class", tuple(ForensicSurfaceClass))
async def test_all_surfaces_derive_both_replay_modes_as_neutral_matches_without_graph_writes(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    surface_class: ForensicSurfaceClass,
) -> None:
    source = await _admitted_source(
        tmp_path,
        sample_campaign,
        surface_class=surface_class,
    )
    source_event_count = len(source.context.graph_store.event_log.events())

    for mode in tuple(replay_module.ForensicEvidenceAnalysisReplayMode):
        independent = (
            mode is replay_module.ForensicEvidenceAnalysisReplayMode.INDEPENDENT_PARSER_COMPARISON
        )
        replay = await _replay_context(
            tmp_path,
            sample_campaign,
            label=mode.value,
            independent=independent,
            surface_class=surface_class,
        )
        replay_event_count = len(replay.graph_store.event_log.events())

        validation = _bind(source, replay)

        assert validation.replay_mode is mode
        assert validation.comparison is (
            replay_module.ForensicEvidenceAnalysisReplayComparison.MATCHED
        )
        assert validation.state == f"{mode.value}-match"
        assert validation.result_body_digest_matched is True
        assert validation.result_bytes_matched is True
        assert validation.result_disposition_matched is True
        assert validation.oracle_disposition_matched is True
        assert validation.review_signal_matched is True
        assert validation.domain_validation_strategy_satisfied is independent
        assert validation.deterministic_parser_coordinates_reused is (not independent)
        assert validation.distinct_parser_implementation_coordinates_verified is independent
        source_implementation = replay_module._parser_implementation_coordinates(
            validation.source_execution
        )
        replay_implementation = replay_module._parser_implementation_coordinates(
            validation.replay_execution
        )
        assert set(source_implementation) == {
            "executionTrustAnchorDigest",
            "activeSignerKeyId",
            "activeSignerPublicKey",
            "sandboxBindingId",
            "sandboxBindingDigest",
            "parserExecutableSHA256",
            "parserConfigurationSHA256",
            "sandboxImageSHA256",
        }
        assert all(
            (source_implementation[name] == replay_implementation[name]) is (not independent)
            for name in source_implementation
        )
        assert (
            validation.source_execution.oracle_verdict.review_signal
            is (_SIGNAL_BY_CLASS[surface_class])
        )
        assert (
            validation.replay_execution.oracle_verdict.review_signal
            is (_SIGNAL_BY_CLASS[surface_class])
        )
        assert validation.source_execution.source_membership_trust_anchor == (
            validation.replay_execution.source_membership_trust_anchor
        )
        assert validation.source_execution.execution_bundle.statement.finished_at < (
            validation.replay_execution.execution_bundle.statement.started_at
        )
        assert validation.signed_timestamp_order_verified is True
        assert validation.self_authenticating_projection is False
        assert validation.source_truth_established is False
        assert validation.parser_correctness_established is False
        assert validation.finding_authority is False
        assert validation.execution_authorized is False
        assert len(source.context.graph_store.event_log.events()) == source_event_count
        assert len(replay.graph_store.event_log.events()) == replay_event_count


@pytest.mark.asyncio
async def test_changed_unresolved_and_inconsistent_equal_digest_results_remain_bounded(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_source(tmp_path / "source", sample_campaign)
    changed_replay = await _replay_context(
        tmp_path,
        sample_campaign,
        label="changed",
        independent=True,
        result_disposition=ForensicEvidenceAnalysisResultDisposition.NO_SIGNAL,
    )
    unresolved_replay = await _replay_context(
        tmp_path,
        sample_campaign,
        label="unresolved",
        independent=False,
        result_body=b"different-bounded-forensic-analysis-result",
    )
    inconsistent_replay = await _replay_context(
        tmp_path,
        sample_campaign,
        label="inconsistent-result-bytes",
        independent=True,
        result_size=4_097,
    )

    changed = _bind(source, changed_replay)
    unresolved = _bind(source, unresolved_replay)

    assert changed.comparison is replay_module.ForensicEvidenceAnalysisReplayComparison.CHANGED
    assert changed.state == "independent-parser-comparison-changed"
    assert changed.result_body_digest_matched is True
    assert changed.result_disposition_matched is False
    assert changed.oracle_disposition_matched is False
    assert changed.review_signal_matched is False
    assert changed.result_truth_established is False
    assert unresolved.comparison is (
        replay_module.ForensicEvidenceAnalysisReplayComparison.UNRESOLVED
    )
    assert unresolved.state == "deterministic-reparse-unresolved"
    assert unresolved.result_body_digest_matched is False
    assert unresolved.result_disposition_matched is True
    assert unresolved.oracle_disposition_matched is True
    assert unresolved.review_signal_matched is True
    assert unresolved.negative_security_claim_established is False

    with pytest.raises(
        replay_module.ForensicEvidenceAnalysisReplayBenchmarkError,
        match="failed closed",
    ):
        _bind(source, inconsistent_replay)


@pytest.mark.asyncio
async def test_partial_parser_drift_reused_context_and_noncausal_replay_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_source(tmp_path / "source", sample_campaign)
    partial_drift = await _replay_context(
        tmp_path,
        sample_campaign,
        label="partial-parser-drift",
        independent=True,
        parser_configuration_sha256=PARSER_CONFIGURATION_DIGEST,
    )
    noncausal_replay = await _replay_context(
        tmp_path,
        sample_campaign,
        label="noncausal-replay",
        independent=True,
        execution_offset=timedelta(),
    )
    source_event_count = len(source.context.graph_store.event_log.events())
    partial_event_count = len(partial_drift.graph_store.event_log.events())
    noncausal_event_count = len(noncausal_replay.graph_store.event_log.events())

    for replay in (partial_drift, noncausal_replay):
        with pytest.raises(
            replay_module.ForensicEvidenceAnalysisReplayBenchmarkError,
            match="failed closed",
        ):
            _bind(source, replay)

    with pytest.raises(
        replay_module.ForensicEvidenceAnalysisReplayBenchmarkError,
        match="failed closed",
    ):
        replay_module.bind_forensic_evidence_analysis_replay(
            source.context.source_inputs,
            source.admission,
            source.context.source_inputs,
            source_root=_context_source_root(source.context),
            replay_root=_context_source_root(source.context),
            source_graph_store=source.context.graph_store,
            replay_graph_store=source.context.graph_store,
            source_membership_trust_anchor=source.context.source_trust_anchor,
            source_execution_trust_anchor=source.context.execution_trust_anchor,
            replay_execution_trust_anchor=source.context.execution_trust_anchor,
        )

    assert len(source.context.graph_store.event_log.events()) == source_event_count
    assert len(partial_drift.graph_store.event_log.events()) == partial_event_count
    assert len(noncausal_replay.graph_store.event_log.events()) == noncausal_event_count


@pytest.mark.asyncio
async def test_contextful_reload_rechecks_stored_admission_roots_stores_and_anchors(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = await _admitted_source(tmp_path / "pair", sample_campaign)
    replay = await _replay_context(
        tmp_path / "pair",
        sample_campaign,
        label="independent-reload",
        independent=True,
    )
    validation = _bind(source, replay)
    wire = validation.model_dump(mode="json", by_alias=True)
    source_event_count = len(source.context.graph_store.event_log.events())
    replay_event_count = len(replay.graph_store.event_log.events())

    assert replay_module.ForensicEvidenceAnalysisReplayValidation.model_validate(wire) == (
        validation
    )
    assert _load(wire, source, replay) == validation

    expected_identity_coordinates = {
        "preparationId",
        "preparationDigest",
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
        "gatewayOutcomeDigest",
        "statementSha256",
        "sourceMembershipAttestationSha256",
        "sourceMembershipVerificationId",
        "sourceMembershipVerificationDigest",
        "sandboxRuntimeReceiptId",
        "sandboxRuntimeReceiptDigest",
        "attestationSha256",
        "resultReceiptId",
        "resultReceiptDigest",
        "resultReceiptSha256",
        "oracleVerdictId",
        "oracleVerdictDigest",
    }
    source_coordinates = replay_module._execution_identity_coordinates(validation.source_execution)
    replay_coordinates = replay_module._execution_identity_coordinates(validation.replay_execution)
    assert set(source_coordinates) == expected_identity_coordinates
    assert set(replay_coordinates) == expected_identity_coordinates
    assert all(
        source_coordinates[name] != replay_coordinates[name]
        for name in expected_identity_coordinates
    )
    real_coordinates = replay_module._execution_identity_coordinates
    for coordinate in expected_identity_coordinates:
        collided = dict(replay_coordinates)
        collided[coordinate] = source_coordinates[coordinate]
        calls = iter((source_coordinates, collided))
        monkeypatch.setattr(
            replay_module,
            "_execution_identity_coordinates",
            lambda _execution, values=calls: next(values),
        )
        with pytest.raises(ValueError, match=rf"reused.*{coordinate}"):
            replay_module._require_distinct_replay_provenance(
                validation.source_execution,
                validation.replay_execution,
            )
    monkeypatch.setattr(
        replay_module,
        "_execution_identity_coordinates",
        real_coordinates,
    )

    drifted_digest = deepcopy(wire)
    drifted_digest["validationDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="validation digest differs"):
        replay_module.ForensicEvidenceAnalysisReplayValidation.model_validate(drifted_digest)

    true_aliases = _literal_marker_aliases(
        replay_module.ForensicEvidenceAnalysisReplayValidation,
        True,
    )
    false_aliases = _literal_marker_aliases(
        replay_module.ForensicEvidenceAnalysisReplayValidation,
        False,
    )
    assert true_aliases
    assert false_aliases
    for aliases, invalid in (
        (true_aliases, 1),
        (false_aliases, 0),
    ):
        coerced = deepcopy(wire)
        coerced["validationId"] = ""
        coerced["validationDigest"] = ""
        coerced.update(dict.fromkeys(aliases, invalid))
        with pytest.raises(ValidationError) as caught:
            replay_module.ForensicEvidenceAnalysisReplayValidation.model_validate(coerced)
        rejected = {str(error["loc"][0]) for error in caught.value.errors()}
        assert aliases.issubset(rejected)

    derived_aliases = {
        "resultBodyDigestMatched",
        "resultBytesMatched",
        "resultDispositionMatched",
        "oracleDispositionMatched",
        "reviewSignalMatched",
        "domainValidationStrategySatisfied",
        "deterministicParserCoordinatesReused",
        "distinctParserImplementationCoordinatesVerified",
    }
    coerced_derived = deepcopy(wire)
    coerced_derived["validationId"] = ""
    coerced_derived["validationDigest"] = ""
    coerced_derived.update(dict.fromkeys(derived_aliases, 1))
    with pytest.raises(ValidationError) as caught:
        replay_module.ForensicEvidenceAnalysisReplayValidation.model_validate(coerced_derived)
    assert derived_aliases.issubset({str(error["loc"][0]) for error in caught.value.errors()})

    hidden = validation.model_copy(deep=True)
    object.__setattr__(hidden.replay_execution.oracle_verdict, "unmodeledAuthority", True)
    with pytest.raises(
        replay_module.ForensicEvidenceAnalysisReplayBenchmarkError,
        match="failed closed",
    ):
        _load(hidden, source, replay)

    foreign_root = tmp_path / "foreign-evidence-root"
    foreign_root.mkdir()
    foreign_store = SQLiteGraphStore(
        tmp_path / "foreign-graph.sqlite3",
        campaign_id=source.admission.candidate.graph.snapshot.campaign_id,
    )
    invalid_contexts = (
        {"source_root": foreign_root},
        {"replay_root": foreign_root},
        {"source_graph_store": foreign_store},
        {"replay_graph_store": source.context.graph_store},
        {
            "source_membership_trust_anchor": _foreign_source_membership_anchor(
                source.context.source_trust_anchor
            )
        },
        {
            "source_execution_trust_anchor": _foreign_execution_anchor(
                source.context.execution_trust_anchor
            )
        },
        {"replay_execution_trust_anchor": _foreign_execution_anchor(replay.execution_trust_anchor)},
    )
    for invalid_context in invalid_contexts:
        with pytest.raises(
            replay_module.ForensicEvidenceAnalysisReplayBenchmarkError,
            match="failed closed",
        ):
            _load(wire, source, replay, **invalid_context)

    assert len(source.context.graph_store.event_log.events()) == source_event_count
    assert len(replay.graph_store.event_log.events()) == replay_event_count


def test_source_imports_exclude_runtime_raw_reader_graph_writer_and_measurement_authority() -> None:
    tree = ast.parse(getsource(replay_module))
    imported_modules: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
            imported_names.update(
                alias.asname or alias.name.rsplit(".", 1)[-1] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            imported_modules.add(node.module or "")
            imported_names.update(alias.asname or alias.name for alias in node.names)

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
        "pajin.graph.admission",
        "pajin.graph.projection",
        "pajin.tools",
    )
    assert not any(
        module == prefix or module.startswith(f"{prefix}.")
        for module in imported_modules
        for prefix in forbidden_module_prefixes
    )
    assert imported_names.isdisjoint(
        {
            "ForensicEvidenceAnalysisTool",
            "GraphAdmissionAuthority",
            "GraphApprovedActionPermitAuthority",
            "GraphApprovedActionPermitDispatcher",
            "GraphProjectionCoordinator",
            "GraphSnapshotAuthority",
            "WorkerJob",
            "WorkerResult",
            "prepare_forensic_evidence_analysis",
        }
    )


def test_capability_grant_semantic_projection_canonicalizes_sets_and_excludes_fresh_identity() -> (
    None
):
    first = CapabilityGrant(
        grant_id="grant_forensics_d_source",
        subject="agent:forensic-evidence-analysis",
        campaign="campaign:forensics-d",
        tools={"pajin.forensics.zeta", "pajin.forensics.alpha"},
        targets={"artifact:zeta", "artifact:alpha"},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        issued_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        expires_at=datetime(2026, 8, 28, 12, 5, tzinfo=UTC),
    )
    second = first.model_copy(
        update={
            "grant_id": "grant_forensics_d_replay",
            "issued_at": datetime(2026, 8, 28, 12, 1, tzinfo=UTC),
            "expires_at": datetime(2026, 8, 28, 12, 6, tzinfo=UTC),
            "tools": {"pajin.forensics.alpha", "pajin.forensics.zeta"},
            "targets": {"artifact:alpha", "artifact:zeta"},
        }
    )

    first_projection = replay_module._capability_grant_semantic_projection(first)
    second_projection = replay_module._capability_grant_semantic_projection(second)

    assert first_projection == second_projection
    assert first_projection["tools"] == ["pajin.forensics.alpha", "pajin.forensics.zeta"]
    assert first_projection["targets"] == ["artifact:alpha", "artifact:zeta"]
    assert "grant_id" not in first_projection
    assert "issued_at" not in first_projection
    assert "expires_at" not in first_projection
    execution_wire = replay_module.ForensicEvidenceAnalysisReplayExecution.model_construct(
        capability_grant=first
    ).model_dump(mode="json", by_alias=True)
    serialized_grant = execution_wire["capabilityGrant"]
    assert serialized_grant["tools"] == [
        "pajin.forensics.alpha",
        "pajin.forensics.zeta",
    ]
    assert serialized_grant["targets"] == ["artifact:alpha", "artifact:zeta"]


def test_seeded_fixture_profile_registers_exact_twelve_unmeasured_forensics_requirements() -> None:
    profile = replay_module.registered_forensic_evidence_analysis_benchmark_fixture_profile()
    plan = resolve_registered_domain_benchmark_plan(profile.domain_benchmark_plan)

    assert profile.state == ("registered-seeded-evidence-requirements-not-materialized-or-measured")
    assert profile.covered_surface_classes == tuple(ForensicSurfaceClass)
    assert profile.required_domain_metric_ids == _FORENSICS_METRIC_IDS
    assert profile.private_ground_truth_requirements_registered is True
    assert profile.private_ground_truth_verified is False
    assert len(profile.cases) == 12
    assert [case.fixture_id for case in profile.cases] == sorted(
        case.fixture_id for case in profile.cases
    )
    assert plan.domain_classification.domain is SecurityDomain.FORENSICS
    assert plan.validation_strategy is DomainValidationStrategy.INDEPENDENT_PARSER_COMPARISON
    forensics_requirements = tuple(
        requirement
        for requirement in plan.metric_requirements
        if requirement.metric.metric_id.startswith("forensics.")
    )
    assert {item.metric.metric_id for item in forensics_requirements} == set(_FORENSICS_METRIC_IDS)
    assert all(
        item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
        for item in forensics_requirements
    )

    for surface_class in ForensicSurfaceClass:
        cases = tuple(case for case in profile.cases if case.surface_class is surface_class)
        assert len(cases) == 3
        by_truth = {case.ground_truth_class: case for case in cases}
        assert set(by_truth) == set(replay_module.ForensicEvidenceBenchmarkGroundTruthClass)
        positive = by_truth[replay_module.ForensicEvidenceBenchmarkGroundTruthClass.KNOWN_POSITIVE]
        negative = by_truth[
            replay_module.ForensicEvidenceBenchmarkGroundTruthClass.NEGATIVE_CONTROL
        ]
        corrupted = by_truth[
            replay_module.ForensicEvidenceBenchmarkGroundTruthClass.CORRUPTED_INPUT_CONTROL
        ]
        mapping = next(
            item
            for item in positive.rule_set.surface_analysis_mapping
            if item.surface_class is surface_class
        )
        for case in cases:
            assert case.input_kind is _INPUT_KIND_BY_CLASS[surface_class]
            assert case.operation is _OPERATION_BY_CLASS[surface_class]
            assert case.input_kind is mapping.input_kind
            assert case.operation is mapping.operation
            assert case.parser is mapping.parser
            assert case.rule_set == positive.rule_set
            assert case.domain_worker_profile == profile.domain_worker_profile
            assert len(case.required_evidence) == 12

        assert positive.expected_outcome is (
            replay_module.ForensicEvidenceBenchmarkExpectedOutcome.REVIEW_SIGNAL
        )
        assert positive.expected_result_disposition is (
            ForensicEvidenceAnalysisResultDisposition.REVIEW
        )
        assert positive.expected_oracle_disposition is (
            ForensicEvidenceAnalysisOracleDisposition.REVIEW
        )
        assert positive.expected_review_signal is _SIGNAL_BY_CLASS[surface_class]
        assert negative.expected_outcome is (
            replay_module.ForensicEvidenceBenchmarkExpectedOutcome.NO_REVIEW_SIGNAL
        )
        assert negative.expected_result_disposition is (
            ForensicEvidenceAnalysisResultDisposition.NO_SIGNAL
        )
        assert negative.expected_oracle_disposition is (
            ForensicEvidenceAnalysisOracleDisposition.NO_SIGNAL
        )
        assert negative.expected_review_signal is None
        assert corrupted.expected_outcome is (
            replay_module.ForensicEvidenceBenchmarkExpectedOutcome.BOUNDED_CORRUPTION_HANDLING
        )
        assert corrupted.expected_result_disposition is None
        assert corrupted.expected_oracle_disposition is None
        assert corrupted.expected_review_signal is None
        assert "source-result-receipt" in positive.required_evidence
        assert "comparison-result-receipt" in positive.required_evidence
        assert "source-result-receipt" in negative.required_evidence
        assert "comparison-result-receipt" in negative.required_evidence
        assert "source-bounded-parser-rejection-receipt" in corrupted.required_evidence
        assert "comparison-bounded-parser-rejection-receipt" in corrupted.required_evidence

    profile_true_aliases = _literal_marker_aliases(type(profile), True)
    profile_false_aliases = _literal_marker_aliases(type(profile), False)
    profile_wire = profile.model_dump(mode="json", by_alias=True)
    assert profile_true_aliases
    assert profile_false_aliases
    assert all(profile_wire[alias] is True for alias in profile_true_aliases)
    assert all(profile_wire[alias] is False for alias in profile_false_aliases)
    assert type(profile).model_validate(profile_wire) == profile


def test_fixture_profile_and_cases_reject_marker_coercion_digest_drift_and_hidden_state() -> None:
    first = replay_module.registered_forensic_evidence_analysis_benchmark_fixture_profile()
    second = replay_module.registered_forensic_evidence_analysis_benchmark_fixture_profile()
    profile_model = replay_module.ForensicEvidenceAnalysisBenchmarkFixtureProfile
    case_model = replay_module.ForensicEvidenceAnalysisBenchmarkFixtureCase

    assert first == second
    assert first is not second
    assert first.cases[0] is not second.cases[0]
    assert first.cases[0].rule_set is not second.cases[0].rule_set

    profile_wire = first.model_dump(mode="json", by_alias=True)
    drifted = deepcopy(profile_wire)
    drifted["profileDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="profile digest differs"):
        profile_model.model_validate(drifted)

    for aliases, invalid in (
        (_literal_marker_aliases(profile_model, True), 0),
        (_literal_marker_aliases(profile_model, False), 1),
    ):
        changed = deepcopy(profile_wire)
        changed["profileId"] = ""
        changed["profileDigest"] = ""
        changed.update(dict.fromkeys(aliases, invalid))
        with pytest.raises(ValidationError) as caught:
            profile_model.model_validate(changed)
        rejected = {str(error["loc"][0]) for error in caught.value.errors()}
        assert aliases.issubset(rejected)

    case_wire = first.cases[0].model_dump(mode="json", by_alias=True)
    case_true_aliases = _literal_marker_aliases(case_model, True)
    case_false_aliases = _literal_marker_aliases(case_model, False)
    case_zero_aliases = {
        field.alias or name
        for name, field in case_model.model_fields.items()
        if get_origin(field.annotation) is Literal
        and len(get_args(field.annotation)) == 1
        and type(get_args(field.annotation)[0]) is int
        and get_args(field.annotation)[0] == 0
    }
    assert case_true_aliases
    assert case_false_aliases
    assert case_zero_aliases
    assert all(case_wire[alias] is True for alias in case_true_aliases)
    assert all(case_wire[alias] is False for alias in case_false_aliases)
    assert all(
        type(case_wire[alias]) is int and case_wire[alias] == 0 for alias in case_zero_aliases
    )
    for aliases, invalid in (
        (case_true_aliases, 0),
        (case_false_aliases, 1),
        (case_zero_aliases, True),
    ):
        changed = deepcopy(case_wire)
        changed.update(dict.fromkeys(aliases, invalid))
        with pytest.raises(ValidationError) as caught:
            case_model.model_validate(changed)
        rejected = {str(error["loc"][0]) for error in caught.value.errors()}
        assert aliases.issubset(rejected)

    hidden = second.model_copy(deep=True)
    object.__setattr__(
        hidden.cases[0].rule_set.surface_analysis_mapping[0],
        "unmodeledAuthority",
        True,
    )
    with pytest.raises(ValidationError, match="unmodeled instance state"):
        profile_model.model_validate(hidden)
