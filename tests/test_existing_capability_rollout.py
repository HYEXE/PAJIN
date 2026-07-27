from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityBenchmarkMapping,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityMaturity,
    CapabilityMetricsReportStatus,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CapabilityUseProfile,
    ExistingModeCapabilityBundle,
    ExistingModeCapabilityReleaseSet,
    ExistingModeCapabilityRollout,
    ExistingModeCapabilityRolloutError,
    admit_existing_mode_capability_releases,
    capability_lifecycle_public_key,
    existing_mode_capability_benchmark_mappings,
    existing_mode_capability_bundle,
    existing_mode_capability_rollout_metrics,
)
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mock import MockAgentProbe

NOW = datetime(2026, 7, 27, 6, tzinfo=UTC)
REVIEWED_AT = NOW - timedelta(days=2)
RELEASED_AT = NOW - timedelta(days=1)


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


def _seed(label: str) -> bytes:
    return sha256(label.encode("utf-8")).digest()


def _signer(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
    key_id: str | None = None,
) -> tuple[CapabilityLifecycleTrustKey, CapabilityLifecycleSigner]:
    key = CapabilityLifecycleTrustKey(
        keyId=key_id or f"test.rollout.{label}",
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


def _signing_authority() -> tuple[
    tuple[CapabilityLifecycleTrustKey, ...],
    CapabilityLifecycleSigner,
    CapabilityLifecycleSigner,
]:
    publisher_key, publisher = _signer(
        "publisher",
        principal="test.rollout.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key, reviewer = _signer(
        "reviewer",
        principal="test.rollout.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    return (publisher_key, reviewer_key), publisher, reviewer


def _signed_releases(
    bundle: ExistingModeCapabilityBundle,
    *,
    policy: CapabilityLifecyclePolicy,
    publisher: CapabilityLifecycleSigner,
    reviewer: CapabilityLifecycleSigner,
) -> tuple[CapabilityReleaseBundle, ...]:
    releases: list[CapabilityReleaseBundle] = []
    for capability in bundle.capabilities():
        reference = capability.reference()
        review = CapabilityReviewStatement(
            capability=reference,
            targetMaturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewerPrincipalId=reviewer.key.principal_id,
            checklistDigest=sha256(
                f"CAP-005 rollout:{reference.capability.capability_id}".encode()
            ).hexdigest(),
            decision=CapabilityReviewDecision.APPROVED,
            issuedAt=REVIEWED_AT,
            expiresAt=NOW + timedelta(days=1),
        )
        signed_review = reviewer.sign_review(review)
        release = CapabilityReleaseStatement(
            capability=reference,
            maturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewDigests=(review.review_digest,),
            publisherPrincipalId=publisher.key.principal_id,
            issuedAt=RELEASED_AT,
        )
        releases.append(
            CapabilityReleaseBundle(
                release=publisher.sign_release(release),
                reviews=(signed_review,),
            )
        )
    return tuple(releases)


def _rollout_inputs() -> tuple[
    ExistingModeCapabilityBundle,
    CapabilityLifecyclePolicy,
    tuple[CapabilityLifecycleTrustKey, ...],
    tuple[CapabilityReleaseBundle, ...],
]:
    bundle = _bundle()
    policy = CapabilityLifecyclePolicy.reference_policy()
    keys, publisher, reviewer = _signing_authority()
    releases = _signed_releases(
        bundle,
        policy=policy,
        publisher=publisher,
        reviewer=reviewer,
    )
    return bundle, policy, keys, releases


def _admit(
    *,
    releases: tuple[CapabilityReleaseBundle, ...] | None = None,
    trust_keys: tuple[CapabilityLifecycleTrustKey, ...] | None = None,
):
    bundle, policy, default_keys, default_releases = _rollout_inputs()
    return admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=default_keys if trust_keys is None else trust_keys,
        releases=default_releases if releases is None else releases,
        clock=lambda: NOW,
    )


def test_existing_mode_benchmark_mappings_cover_exact_seven_capabilities() -> None:
    bundle = _bundle()

    mappings = existing_mode_capability_benchmark_mappings(bundle)

    assert len(mappings) == 7
    assert {item.capability for item in mappings} == {
        item.capability for item in bundle.capabilities()
    }
    assert len({item.mapping_digest for item in mappings}) == 7
    assert all(item.benchmark_ids[0].startswith("pajin.benchmark.") for item in mappings)
    assert mappings == existing_mode_capability_benchmark_mappings(bundle)


def test_rollout_verifies_all_external_signatures_and_is_order_independent() -> None:
    bundle, policy, keys, releases = _rollout_inputs()

    forward = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: NOW,
    )
    reverse = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=tuple(reversed(keys)),
        releases=tuple(reversed(releases)),
        clock=lambda: NOW,
    )

    assert forward.release_set.release_set_digest == (reverse.release_set.release_set_digest)
    assert len(forward.release_set.bindings) == 7
    assert forward.release_set.policy_digest == policy.digest
    for binding in forward.release_set.bindings:
        resolved = forward.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        assert resolved.capability.reference() == binding.capability
        assert resolved.maturity is CapabilityMaturity.EXPERIMENTAL


def test_rollout_metrics_promote_only_verified_mapping_and_lifecycle_coverage() -> None:
    rollout = _admit()

    report = existing_mode_capability_rollout_metrics(
        rollout,
        measured_at=NOW,
    )

    assert report.status is CapabilityMetricsReportStatus.INCOMPLETE
    assert report.registry.definition_coverage.value == 1
    assert report.registry.authority_coverage.value == 1
    assert report.registry.benchmark_mapping_coverage.value == 1
    assert report.lead_time.delivery_coverage.value == 0
    assert report.oracle.authority_coverage.value == 1
    assert report.oracle.observation_coverage.value == 0
    assert report.replay.support_coverage.value == 1
    assert report.replay.observation_coverage.value == 0
    assert report.lifecycle.release_coverage.value == 1
    assert report.lifecycle.experimental_count == 7
    assert len(report.inputs.benchmark_mapping_digests) == 7
    assert len(report.inputs.lifecycle_release_digests) == 7
    assert len(report.gaps) == 17


def test_rollout_rejects_missing_and_duplicate_release_inventory() -> None:
    bundle, policy, keys, releases = _rollout_inputs()

    with pytest.raises(ExistingModeCapabilityRolloutError, match="exactly seven"):
        admit_existing_mode_capability_releases(
            bundle=bundle,
            policy=policy,
            trust_keys=keys,
            releases=releases[:-1],
            clock=lambda: NOW,
        )
    duplicated = (*releases[:-1], releases[0])
    with pytest.raises(
        ExistingModeCapabilityRolloutError,
        match="failed lifecycle verification",
    ):
        admit_existing_mode_capability_releases(
            bundle=bundle,
            policy=policy,
            trust_keys=keys,
            releases=duplicated,
            clock=lambda: NOW,
        )


def test_rollout_rejects_signature_authority_substitution() -> None:
    bundle, policy, keys, releases = _rollout_inputs()
    substituted_key, _substituted_signer = _signer(
        "substituted-reviewer",
        principal=keys[1].principal_id,
        role=CapabilityLifecycleKeyRole.REVIEWER,
        key_id=keys[1].key_id,
    )

    with pytest.raises(
        ExistingModeCapabilityRolloutError,
        match="failed lifecycle verification",
    ):
        admit_existing_mode_capability_releases(
            bundle=bundle,
            policy=policy,
            trust_keys=(keys[0], substituted_key),
            releases=releases,
            clock=lambda: NOW,
        )


def test_release_set_and_rollout_reject_identity_and_mapping_drift() -> None:
    rollout = _admit()
    payload = rollout.release_set.model_dump(mode="json", by_alias=True)
    payload["releaseSetDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="release-set digest"):
        ExistingModeCapabilityReleaseSet.model_validate(payload)

    first = rollout.benchmark_mappings[0]
    drifted = CapabilityBenchmarkMapping(
        capability=first.capability,
        benchmarkIds=first.benchmark_ids,
        expectedObservables=("A different observable was substituted.",),
    )
    mappings = tuple(
        sorted(
            (drifted, *rollout.benchmark_mappings[1:]),
            key=lambda item: (
                item.capability.capability_id,
                item.capability.capability_version,
                item.capability.capability_digest,
            ),
        )
    )
    with pytest.raises(
        ExistingModeCapabilityRolloutError,
        match="differ from code authority",
    ):
        ExistingModeCapabilityRollout(
            bundle=rollout.bundle,
            lifecycle=rollout.lifecycle,
            release_set=rollout.release_set,
            benchmark_mappings=mappings,
        )
