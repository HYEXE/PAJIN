from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityBenchmarkMapping,
    CapabilityDeliveryEvidence,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityMaturity,
    CapabilityMetricRequirement,
    CapabilityMetricScope,
    CapabilityMetricsReportStatus,
    CapabilityOracleDecision,
    CapabilityOracleObservation,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReplayObservation,
    CapabilityReplaySupport,
    CapabilityReplayVerdict,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CodeBackedCapability,
    ExistingModeCapabilityBundle,
    build_capability_registry_metrics,
    capability_lifecycle_public_key,
    existing_mode_capability_bundle,
    existing_mode_capability_metrics_baseline,
    existing_mode_capability_replay_support,
)
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mock import MockAgentProbe

NOW = datetime(2026, 7, 27, 3, tzinfo=UTC)
AUTHORED_AT = NOW - timedelta(days=7)
CODE_BACKED_AT = NOW - timedelta(days=5)
REVIEWED_AT = NOW - timedelta(days=3)
RELEASED_AT = NOW - timedelta(days=2)
BENCHMARK_ID = "benchmark.kisa.system-prompt-disclosure"
CAPABILITY_ID = "pajin.ai.kisa.system-prompt-disclosure"


@dataclass(frozen=True, slots=True)
class _CompleteInputs:
    mapping: CapabilityBenchmarkMapping
    delivery: CapabilityDeliveryEvidence
    oracle: tuple[CapabilityOracleObservation, ...]
    support: CapabilityReplaySupport
    replay: tuple[CapabilityReplayObservation, ...]
    lifecycle: CapabilityLifecycleRegistry


def _bundle() -> ExistingModeCapabilityBundle:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
    ):
        tools.register(tool)
    return existing_mode_capability_bundle(tools)


def _manifest(
    bundle: ExistingModeCapabilityBundle,
    capability_id: str = CAPABILITY_ID,
) -> CodeBackedCapability:
    return next(
        item for item in bundle.capabilities() if item.capability.capability_id == capability_id
    )


def _one_capability_scope(
    manifest: CodeBackedCapability,
    *,
    replay_required: bool = True,
) -> CapabilityMetricScope:
    return CapabilityMetricScope(
        scopeId="test.capability-metrics",
        scopeVersion="1.0.0",
        requirements=(
            CapabilityMetricRequirement(
                capability=manifest.reference(),
                replayRequired=replay_required,
            ),
        ),
    )


def _seed(label: str) -> bytes:
    return sha256(label.encode("utf-8")).digest()


def _signer(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> tuple[CapabilityLifecycleTrustKey, CapabilityLifecycleSigner]:
    key = CapabilityLifecycleTrustKey(
        keyId=f"test.metrics.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
    )
    return (
        key,
        CapabilityLifecycleSigner.from_private_key_bytes(
            key=key,
            private_key=_seed(label),
        ),
    )


def _signed_lifecycle(
    bundle: ExistingModeCapabilityBundle,
    manifest: CodeBackedCapability,
) -> tuple[CapabilityLifecycleRegistry, CapabilityReleaseStatement]:
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key, publisher = _signer(
        "publisher",
        principal="test.metrics.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key, reviewer = _signer(
        "reviewer",
        principal="test.metrics.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    review = CapabilityReviewStatement(
        capability=manifest.reference(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"CAP-006 checklist").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=REVIEWED_AT,
        expiresAt=NOW + timedelta(days=1),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=manifest.reference(),
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(review.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=RELEASED_AT,
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(
            CapabilityReleaseBundle(
                release=publisher.sign_release(release),
                reviews=(signed_review,),
            ),
        ),
        clock=lambda: NOW,
    )
    return lifecycle, release


def _complete_inputs(
    bundle: ExistingModeCapabilityBundle,
    manifest: CodeBackedCapability,
    *,
    second_observation: bool = False,
) -> _CompleteInputs:
    lifecycle, release = _signed_lifecycle(bundle, manifest)
    mapping = CapabilityBenchmarkMapping(
        capability=manifest.capability,
        benchmarkIds=(BENCHMARK_ID,),
        expectedObservables=("The registered Success Oracle emits a decision.",),
    )
    delivery = CapabilityDeliveryEvidence(
        capability=manifest.reference(),
        authoredAt=AUTHORED_AT,
        codeBackedAt=CODE_BACKED_AT,
        releasedAt=RELEASED_AT,
        release=release.reference(),
        sourceDigest=sha256(b"CAP-006 delivery source").hexdigest(),
    )
    oracle = [
        CapabilityOracleObservation(
            capability=manifest.reference(),
            benchmarkId=BENCHMARK_ID,
            decision=CapabilityOracleDecision.SUCCEEDED,
            observedAt=NOW - timedelta(hours=4),
            evidenceDigest=sha256(b"Oracle sample A").hexdigest(),
        )
    ]
    support = next(
        item
        for item in existing_mode_capability_replay_support(bundle)
        if item.capability == manifest.reference()
    )
    replay = [
        CapabilityReplayObservation(
            capability=manifest.reference(),
            contractId=support.contract_ids[0],
            verdict=CapabilityReplayVerdict.SUPPORTS,
            observedAt=NOW - timedelta(hours=3),
            evidenceDigest=sha256(b"Replay sample A").hexdigest(),
        )
    ]
    if second_observation:
        oracle.append(
            CapabilityOracleObservation(
                capability=manifest.reference(),
                benchmarkId=BENCHMARK_ID,
                decision=CapabilityOracleDecision.INCONCLUSIVE,
                observedAt=NOW - timedelta(hours=2),
                evidenceDigest=sha256(b"Oracle sample B").hexdigest(),
            )
        )
        replay.append(
            CapabilityReplayObservation(
                capability=manifest.reference(),
                contractId=support.contract_ids[-1],
                verdict=CapabilityReplayVerdict.CONTRADICTS,
                observedAt=NOW - timedelta(hours=1),
                evidenceDigest=sha256(b"Replay sample B").hexdigest(),
            )
        )
    return _CompleteInputs(
        mapping=mapping,
        delivery=delivery,
        oracle=tuple(oracle),
        support=support,
        replay=tuple(replay),
        lifecycle=lifecycle,
    )


def _complete_report(
    bundle: ExistingModeCapabilityBundle,
    manifest: CodeBackedCapability,
    inputs: _CompleteInputs,
    *,
    oracle: tuple[CapabilityOracleObservation, ...] | None = None,
    replay: tuple[CapabilityReplayObservation, ...] | None = None,
):
    return build_capability_registry_metrics(
        scope=_one_capability_scope(manifest),
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        measured_at=NOW,
        benchmark_mappings=(inputs.mapping,),
        delivery_evidence=(inputs.delivery,),
        oracle_observations=inputs.oracle if oracle is None else oracle,
        replay_support=(inputs.support,),
        replay_observations=inputs.replay if replay is None else replay,
        lifecycle=inputs.lifecycle,
    )


def test_existing_mode_baseline_reports_implemented_structure_and_explicit_gaps() -> None:
    bundle = _bundle()

    report = existing_mode_capability_metrics_baseline(
        bundle,
        measured_at=NOW,
    )

    assert report.status is CapabilityMetricsReportStatus.INCOMPLETE
    assert report.registry.definition_coverage.value == 1
    assert report.registry.authority_coverage.value == 1
    assert report.registry.benchmark_mapping_coverage.value == 0
    assert report.lead_time.delivery_coverage.value == 0
    assert report.oracle.authority_coverage.value == 1
    assert report.oracle.observation_coverage.value == 0
    assert report.oracle.determinate_rate.denominator == 0
    assert report.oracle.determinate_rate.value is None
    assert report.replay.support_coverage.value == 1
    assert report.replay.observation_coverage.value == 0
    assert report.replay.support_rate.denominator == 0
    assert report.replay.support_rate.value is None
    assert report.lifecycle.release_coverage.value == 0
    assert len(report.gaps) == 31
    assert report == existing_mode_capability_metrics_baseline(
        bundle,
        measured_at=NOW,
    )


def test_complete_report_binds_registry_lead_oracle_replay_and_lifecycle() -> None:
    bundle = _bundle()
    manifest = _manifest(bundle)
    inputs = _complete_inputs(bundle, manifest)

    report = _complete_report(bundle, manifest, inputs)

    assert report.status is CapabilityMetricsReportStatus.COMPLETE
    assert report.gaps == ()
    assert report.registry.definition_coverage.value == 1
    assert report.registry.authority_coverage.value == 1
    assert report.registry.benchmark_mapping_coverage.value == 1
    assert report.lead_time.delivery_coverage.value == 1
    assert report.lead_time.release_lead_time_coverage.value == 1
    assert report.lead_time.authored_to_code_backed is not None
    assert report.lead_time.authored_to_code_backed.median_seconds == 2 * 24 * 60 * 60
    assert report.lead_time.authored_to_release is not None
    assert report.lead_time.authored_to_release.median_seconds == 5 * 24 * 60 * 60
    assert report.oracle.observation_count == 1
    assert report.oracle.determinate_rate.value == 1
    assert report.replay.observation_count == 1
    assert report.replay.support_rate.value == 1
    assert report.lifecycle.experimental_count == 1
    assert report.inputs.benchmark_mapping_digests == (inputs.mapping.mapping_digest,)
    assert report.inputs.delivery_evidence_digests == (inputs.delivery.evidence_digest,)


def test_observation_order_does_not_change_report_identity() -> None:
    bundle = _bundle()
    manifest = _manifest(bundle)
    inputs = _complete_inputs(bundle, manifest, second_observation=True)

    forward = _complete_report(bundle, manifest, inputs)
    reverse = _complete_report(
        bundle,
        manifest,
        inputs,
        oracle=tuple(reversed(inputs.oracle)),
        replay=tuple(reversed(inputs.replay)),
    )

    assert forward.report_digest == reverse.report_digest
    assert forward.oracle.observation_count == 2
    assert forward.oracle.determinate_rate.value == 0.5
    assert forward.replay.observation_count == 2
    assert forward.replay.support_rate.value == 0.5


def test_scope_and_delivery_records_reject_tampering_and_invalid_time_order() -> None:
    bundle = _bundle()
    manifest = _manifest(bundle)
    scope = _one_capability_scope(manifest)

    scope_payload = scope.model_dump(mode="json", by_alias=True)
    scope_payload["scopeDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="scope digest"):
        CapabilityMetricScope.model_validate(scope_payload)
    with pytest.raises(ValidationError, match="predates authoring"):
        CapabilityDeliveryEvidence(
            capability=manifest.reference(),
            authoredAt=CODE_BACKED_AT,
            codeBackedAt=AUTHORED_AT,
            sourceDigest=sha256(b"invalid delivery").hexdigest(),
        )
    with pytest.raises(ValidationError, match="require a benchmark mapping"):
        CapabilityMetricRequirement(
            capability=manifest.reference(),
            benchmarkRequired=False,
            oracleObservationRequired=True,
        )


def test_collector_rejects_foreign_duplicate_and_authority_drifted_evidence() -> None:
    bundle = _bundle()
    manifest = _manifest(bundle)
    other = next(item for item in bundle.capabilities() if item != manifest)
    scope = _one_capability_scope(manifest)
    foreign_mapping = CapabilityBenchmarkMapping(
        capability=other.capability,
        benchmarkIds=("benchmark.foreign",),
        expectedObservables=("Foreign evidence is not counted.",),
    )
    with pytest.raises(ValueError, match="out-of-scope"):
        build_capability_registry_metrics(
            scope=scope,
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            measured_at=NOW,
            benchmark_mappings=(foreign_mapping,),
        )

    observation = CapabilityOracleObservation(
        capability=manifest.reference(),
        benchmarkId=BENCHMARK_ID,
        decision=CapabilityOracleDecision.SUCCEEDED,
        observedAt=NOW,
        evidenceDigest=sha256(b"duplicate").hexdigest(),
    )
    with pytest.raises(ValueError, match="duplicated"):
        build_capability_registry_metrics(
            scope=scope,
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            measured_at=NOW,
            oracle_observations=(observation, observation),
        )

    drifted_reference = manifest.reference().model_copy(update={"authority_set_digest": "0" * 64})
    delivery = CapabilityDeliveryEvidence(
        capability=drifted_reference,
        authoredAt=AUTHORED_AT,
        codeBackedAt=CODE_BACKED_AT,
        sourceDigest=sha256(b"drifted delivery").hexdigest(),
    )
    with pytest.raises(ValueError, match="metric scope authority"):
        build_capability_registry_metrics(
            scope=scope,
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            measured_at=NOW,
            delivery_evidence=(delivery,),
        )


def test_collector_rejects_unmapped_oracle_and_unsupported_replay_samples() -> None:
    bundle = _bundle()
    manifest = _manifest(bundle)
    inputs = _complete_inputs(bundle, manifest)
    unmapped = CapabilityOracleObservation(
        capability=manifest.reference(),
        benchmarkId="benchmark.not-mapped",
        decision=CapabilityOracleDecision.SUCCEEDED,
        observedAt=NOW,
        evidenceDigest=sha256(b"unmapped Oracle").hexdigest(),
    )
    with pytest.raises(ValueError, match="outside the exact mapping"):
        _complete_report(
            bundle,
            manifest,
            inputs,
            oracle=(unmapped,),
        )

    unsupported = CapabilityReplayObservation(
        capability=manifest.reference(),
        contractId="replay.unsupported",
        verdict=CapabilityReplayVerdict.SUPPORTS,
        observedAt=NOW,
        evidenceDigest=sha256(b"unsupported Replay").hexdigest(),
    )
    with pytest.raises(ValueError, match="outside exact Replay support"):
        _complete_report(
            bundle,
            manifest,
            inputs,
            replay=(unsupported,),
        )


def test_optional_dimensions_use_empty_denominators_without_inventing_zero_rates() -> None:
    bundle = _bundle()
    manifest = _manifest(bundle)
    scope = CapabilityMetricScope(
        scopeId="test.optional-capability-metrics",
        scopeVersion="1.0.0",
        requirements=(
            CapabilityMetricRequirement(
                capability=manifest.reference(),
                benchmarkRequired=False,
                deliveryEvidenceRequired=False,
                oracleObservationRequired=False,
                replayRequired=False,
                lifecycleRequired=False,
            ),
        ),
    )

    report = build_capability_registry_metrics(
        scope=scope,
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        measured_at=NOW,
    )

    assert report.status is CapabilityMetricsReportStatus.COMPLETE
    assert report.registry.benchmark_mapping_coverage.denominator == 0
    assert report.registry.benchmark_mapping_coverage.value is None
    assert report.lead_time.delivery_coverage.value is None
    assert report.oracle.observation_coverage.value is None
    assert report.replay.support_coverage.value is None
    assert report.lifecycle.release_coverage.value is None
