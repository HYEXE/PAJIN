from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import JsonValue, ValidationError

from pajin.capabilities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityDefinition,
    CapabilityDefinitionRegistry,
    CapabilityDeprecationNotice,
    CapabilityLifecycleError,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityMaturity,
    CapabilityOracleDecision,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    CapabilityUseProfile,
    CodeBackedCapabilityRef,
    capability_lifecycle_public_key,
)
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult

NOW = datetime(2026, 1, 10, tzinfo=UTC)
DIGEST_A = sha256(b"schema").hexdigest()
DIGEST_B = sha256(b"tool").hexdigest()


class _Authority:
    def __init__(
        self,
        definition: CapabilityDefinition,
        role: CapabilityAuthorityRole,
    ) -> None:
        self.authority_role = role
        self.authority_id = f"test.lifecycle.{definition.capability_version}.{role.value}"
        self.authority_version = "1.0.0"
        self.capability_reference = definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "implementationVersion": "test.lifecycle-authority/v1",
            "role": self.authority_role.value,
        }

    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        return parameters

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        del materialized_arguments
        return request

    def prepare(self, request: ToolRequest) -> WorkerJob:
        del request
        raise NotImplementedError

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del request, result
        raise NotImplementedError

    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None


def _definition(
    version: str,
    maturity: CapabilityMaturity,
    *,
    capability_id: str = "pajin.discovery.lifecycle-test",
) -> CapabilityDefinition:
    return CapabilityDefinition(
        capabilityId=capability_id,
        capabilityVersion=version,
        domain="web",
        maturity=maturity,
        supportedSurfaceTypes=("http-endpoint",),
        threatClasses=("surface-discovery",),
        parameterSchemaDigest=DIGEST_A,
        tool=CapabilityToolBinding(
            toolId="test.read-surface",
            toolVersion="1.0.0",
            toolDigest=DIGEST_B,
        ),
        riskTier=ToolRiskTier.T1,
        sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
        evidenceTypes=("json",),
        networkAccess=False,
        approvalRequired=False,
        requestUnitCost=1,
        cleanupRequired=False,
        parallelSafe=True,
    )


def _registries(
    definitions: list[CapabilityDefinition],
) -> tuple[
    CapabilityDefinitionRegistry,
    CapabilityAuthorityRegistry,
    dict[str, CodeBackedCapabilityRef],
]:
    definition_registry = CapabilityDefinitionRegistry(definitions)
    adapters: list[CapabilityAuthorityAdapter] = [
        _Authority(definition, role)
        for definition in definitions
        for role in CapabilityAuthorityRole
    ]
    authority_registry = CapabilityAuthorityRegistry(
        definition_registry,
        adapters,
    )
    references = {
        manifest.capability.capability_version: manifest.reference()
        for manifest in authority_registry.capabilities()
    }
    return definition_registry, authority_registry, references


def _seed(label: str) -> bytes:
    return sha256(label.encode("utf-8")).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
    state: CapabilityLifecycleKeyState = CapabilityLifecycleKeyState.ACTIVE,
    not_after: datetime | None = None,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"test.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=state,
        notBefore=NOW - timedelta(days=30),
        notAfter=not_after,
    )


def _signer(key: CapabilityLifecycleTrustKey, label: str) -> CapabilityLifecycleSigner:
    return CapabilityLifecycleSigner.from_private_key_bytes(
        key=key,
        private_key=_seed(label),
    )


def _bundle(
    *,
    capability: CodeBackedCapabilityRef,
    maturity: CapabilityMaturity,
    sequence: int,
    previous_digest: str | None,
    policy: CapabilityLifecyclePolicy,
    publisher: CapabilityLifecycleSigner,
    reviewers: list[CapabilityLifecycleSigner],
    notice: CapabilityDeprecationNotice | None = None,
    decision: CapabilityReviewDecision = CapabilityReviewDecision.APPROVED,
    review_valid_for: timedelta = timedelta(days=7),
) -> CapabilityReleaseBundle:
    review_time = NOW - timedelta(days=2) + timedelta(hours=sequence)
    signed_reviews = []
    for reviewer in reviewers:
        review = CapabilityReviewStatement(
            capability=capability,
            targetMaturity=maturity,
            sequence=sequence,
            previousReleaseDigest=previous_digest,
            policyDigest=policy.digest,
            reviewerPrincipalId=reviewer.key.principal_id,
            checklistDigest=sha256(
                f"{capability.capability.capability_version}:{reviewer.key.principal_id}".encode()
            ).hexdigest(),
            decision=decision,
            issuedAt=review_time,
            expiresAt=review_time + review_valid_for,
        )
        signed_reviews.append(reviewer.sign_review(review))
    signed_reviews.sort(key=lambda item: item.statement.review_digest)
    release = CapabilityReleaseStatement(
        capability=capability,
        maturity=maturity,
        sequence=sequence,
        previousReleaseDigest=previous_digest,
        policyDigest=policy.digest,
        reviewDigests=tuple(review.statement.review_digest for review in signed_reviews),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=review_time + timedelta(hours=1),
        deprecation=notice,
    )
    return CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=tuple(signed_reviews),
    )


def _keys_and_signers() -> tuple[
    list[CapabilityLifecycleTrustKey],
    CapabilityLifecycleSigner,
    CapabilityLifecycleSigner,
    CapabilityLifecycleSigner,
]:
    publisher_key = _trust_key(
        "publisher",
        principal="team.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_a_key = _trust_key(
        "reviewer-a",
        principal="team.reviewer-a",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    reviewer_b_key = _trust_key(
        "reviewer-b",
        principal="team.reviewer-b",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    return (
        [publisher_key, reviewer_a_key, reviewer_b_key],
        _signer(publisher_key, "publisher"),
        _signer(reviewer_a_key, "reviewer-a"),
        _signer(reviewer_b_key, "reviewer-b"),
    )


def _registry(
    *,
    definitions: CapabilityDefinitionRegistry,
    authorities: CapabilityAuthorityRegistry,
    policy: CapabilityLifecyclePolicy,
    keys: list[CapabilityLifecycleTrustKey],
    releases: list[CapabilityReleaseBundle],
) -> CapabilityLifecycleRegistry:
    return CapabilityLifecycleRegistry(
        definitions=definitions,
        authorities=authorities,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: NOW,
    )


def test_signed_release_chain_gates_exact_current_maturity_and_profile() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definitions = [
        _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL),
        _definition("1.1.0", CapabilityMaturity.CANARY),
        _definition("2.0.0", CapabilityMaturity.STABLE),
    ]
    definition_registry, authorities, references = _registries(definitions)
    keys, publisher, reviewer_a, reviewer_b = _keys_and_signers()
    experimental = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    canary = _bundle(
        capability=references["1.1.0"],
        maturity=CapabilityMaturity.CANARY,
        sequence=2,
        previous_digest=experimental.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    stable = _bundle(
        capability=references["2.0.0"],
        maturity=CapabilityMaturity.STABLE,
        sequence=3,
        previous_digest=canary.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a, reviewer_b],
    )
    registry = _registry(
        definitions=definition_registry,
        authorities=authorities,
        policy=policy,
        keys=keys,
        releases=[stable, experimental, canary],
    )

    resolved = registry.resolve_for_use(
        stable.release.statement.reference(),
        CapabilityUseProfile.PENTEST,
    )
    assert resolved.maturity is CapabilityMaturity.STABLE
    assert resolved.capability.reference() == references["2.0.0"]
    assert registry.head(definitions[0].capability_id) == stable.release.statement.reference()
    assert registry.resolve_release(experimental.release.statement.reference()) == experimental
    with pytest.raises(CapabilityLifecycleError, match="historical"):
        registry.resolve_for_use(
            experimental.release.statement.reference(),
            CapabilityUseProfile.RANGE,
        )


def test_experimental_is_range_only_and_stable_requires_two_reviewers() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definitions = [
        _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL),
        _definition("2.0.0", CapabilityMaturity.STABLE),
    ]
    definition_registry, authorities, references = _registries(definitions)
    keys, publisher, reviewer_a, _ = _keys_and_signers()
    experimental = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    experimental_registry = _registry(
        definitions=definition_registry,
        authorities=authorities,
        policy=policy,
        keys=keys,
        releases=[experimental],
    )
    assert (
        experimental_registry.resolve_for_use(
            experimental.release.statement.reference(),
            CapabilityUseProfile.RANGE,
        ).profile
        is CapabilityUseProfile.RANGE
    )
    with pytest.raises(CapabilityLifecycleError, match="cannot run"):
        experimental_registry.resolve_for_use(
            experimental.release.statement.reference(),
            CapabilityUseProfile.BUG_HUNT,
        )

    under_reviewed_stable = _bundle(
        capability=references["2.0.0"],
        maturity=CapabilityMaturity.STABLE,
        sequence=2,
        previous_digest=experimental.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    with pytest.raises(CapabilityLifecycleError, match="quorum"):
        _registry(
            definitions=definition_registry,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[experimental, under_reviewed_stable],
        )


def test_signatures_principal_separation_and_revocation_fail_closed() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definition = _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL)
    definitions, authorities, references = _registries([definition])
    keys, publisher, reviewer_a, _ = _keys_and_signers()
    bundle = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    signature = bundle.release.signature_base64url
    tampered_release = bundle.release.model_copy(
        update={"signature_base64url": ("A" if signature[0] != "A" else "B") + signature[1:]}
    )
    tampered = bundle.model_copy(update={"release": tampered_release})
    with pytest.raises(CapabilityLifecycleError, match="signature verification"):
        _registry(
            definitions=definitions,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[tampered],
        )

    reviewer_key = keys[1]
    revoked_reviewer = reviewer_key.model_copy(
        update={
            "state": CapabilityLifecycleKeyState.REVOKED,
            "revoked_at": NOW - timedelta(days=1),
        }
    )
    with pytest.raises(CapabilityLifecycleError, match="revoked"):
        _registry(
            definitions=definitions,
            authorities=authorities,
            policy=policy,
            keys=[keys[0], revoked_reviewer, keys[2]],
            releases=[bundle],
        )

    self_review_key = _trust_key(
        "self-review",
        principal=publisher.key.principal_id,
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    self_review = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[_signer(self_review_key, "self-review")],
    )
    with pytest.raises(CapabilityLifecycleError, match="own release"):
        _registry(
            definitions=definitions,
            authorities=authorities,
            policy=policy,
            keys=[keys[0], self_review_key],
            releases=[self_review],
        )

    rejected = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
        decision=CapabilityReviewDecision.REJECTED,
    )
    with pytest.raises(CapabilityLifecycleError, match="rejected"):
        _registry(
            definitions=definitions,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[rejected],
        )

    expired = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
        review_valid_for=timedelta(minutes=30),
    )
    with pytest.raises(CapabilityLifecycleError, match="not valid"):
        _registry(
            definitions=definitions,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[expired],
        )


def test_chain_rejects_skips_illegal_transitions_and_definition_reuse() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definitions = [
        _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL),
        _definition("1.1.0", CapabilityMaturity.CANARY),
        _definition("2.0.0", CapabilityMaturity.STABLE),
    ]
    definition_registry, authorities, references = _registries(definitions)
    keys, publisher, reviewer_a, reviewer_b = _keys_and_signers()
    first = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    skipped = _bundle(
        capability=references["1.1.0"],
        maturity=CapabilityMaturity.CANARY,
        sequence=3,
        previous_digest=first.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    with pytest.raises(CapabilityLifecycleError, match="sequence"):
        _registry(
            definitions=definition_registry,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[first, skipped],
        )

    direct_stable = _bundle(
        capability=references["2.0.0"],
        maturity=CapabilityMaturity.STABLE,
        sequence=2,
        previous_digest=first.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a, reviewer_b],
    )
    with pytest.raises(CapabilityLifecycleError, match="cannot transition"):
        _registry(
            definitions=definition_registry,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[first, direct_stable],
        )

    reused = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=2,
        previous_digest=first.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    with pytest.raises(CapabilityLifecycleError, match="new immutable definition"):
        _registry(
            definitions=definition_registry,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[first, reused],
        )


def test_deprecation_and_retirement_are_not_executable_and_require_notice() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definitions = [
        _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL),
        _definition("1.1.0", CapabilityMaturity.CANARY),
        _definition("1.2.0", CapabilityMaturity.DEPRECATED),
        _definition("1.3.0", CapabilityMaturity.RETIRED),
    ]
    definition_registry, authorities, references = _registries(definitions)
    keys, publisher, reviewer_a, _ = _keys_and_signers()
    first = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    canary = _bundle(
        capability=references["1.1.0"],
        maturity=CapabilityMaturity.CANARY,
        sequence=2,
        previous_digest=first.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    notice = CapabilityDeprecationNotice(
        reasonCode="superseded",
        summary="Capability is replaced by a safer implementation.",
        announcedAt=NOW - timedelta(days=3),
        effectiveAt=NOW - timedelta(days=1),
    )
    deprecated = _bundle(
        capability=references["1.2.0"],
        maturity=CapabilityMaturity.DEPRECATED,
        sequence=3,
        previous_digest=canary.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
        notice=notice,
    )
    retired = _bundle(
        capability=references["1.3.0"],
        maturity=CapabilityMaturity.RETIRED,
        sequence=4,
        previous_digest=deprecated.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[],
        notice=notice,
    )
    registry = _registry(
        definitions=definition_registry,
        authorities=authorities,
        policy=policy,
        keys=keys,
        releases=[first, canary, deprecated, retired],
    )
    with pytest.raises(CapabilityLifecycleError, match="cannot run"):
        registry.resolve_for_use(
            retired.release.statement.reference(),
            CapabilityUseProfile.RANGE,
        )

    self_replacement_notice = notice.model_copy(update={"replacement": references["1.2.0"]})
    invalid_replacement = _bundle(
        capability=references["1.2.0"],
        maturity=CapabilityMaturity.DEPRECATED,
        sequence=3,
        previous_digest=canary.release.statement.release_digest,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
        notice=self_replacement_notice,
    )
    with pytest.raises(CapabilityLifecycleError, match="reference itself"):
        _registry(
            definitions=definition_registry,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[first, canary, invalid_replacement],
        )

    with pytest.raises(ValidationError, match="deprecation notice"):
        CapabilityReleaseStatement(
            capability=references["1.2.0"],
            maturity=CapabilityMaturity.DEPRECATED,
            sequence=3,
            previousReleaseDigest=canary.release.statement.release_digest,
            policyDigest=policy.digest,
            reviewDigests=(),
            publisherPrincipalId=publisher.key.principal_id,
            issuedAt=NOW,
        )


def test_retired_key_verifies_history_but_cannot_create_a_signer() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definition = _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL)
    definitions, authorities, references = _registries([definition])
    keys, publisher, reviewer_a, _ = _keys_and_signers()
    bundle = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    retired_publisher = keys[0].model_copy(
        update={
            "state": CapabilityLifecycleKeyState.RETIRED,
            "not_after": NOW - timedelta(hours=1),
        }
    )
    registry = _registry(
        definitions=definitions,
        authorities=authorities,
        policy=policy,
        keys=[retired_publisher, keys[1], keys[2]],
        releases=[bundle],
    )
    assert registry.resolve_release(bundle.release.statement.reference()) == bundle
    with pytest.raises(ValueError, match="active key"):
        CapabilityLifecycleSigner.from_private_key_bytes(
            key=retired_publisher,
            private_key=_seed("publisher"),
        )


def test_release_bundle_rejects_review_set_omission() -> None:
    policy = CapabilityLifecyclePolicy.reference_policy()
    definition = _definition("1.0.0", CapabilityMaturity.EXPERIMENTAL)
    definitions, authorities, references = _registries([definition])
    keys, publisher, reviewer_a, _ = _keys_and_signers()
    bundle = _bundle(
        capability=references["1.0.0"],
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previous_digest=None,
        policy=policy,
        publisher=publisher,
        reviewers=[reviewer_a],
    )
    with pytest.raises(ValidationError, match="review set differs"):
        CapabilityReleaseBundle(
            release=bundle.release,
            reviews=(),
        )

    bypassed = bundle.model_copy(update={"reviews": ()})
    with pytest.raises(CapabilityLifecycleError, match="bundle is not canonical"):
        _registry(
            definitions=definitions,
            authorities=authorities,
            policy=policy,
            keys=keys,
            releases=[bypassed],
        )
