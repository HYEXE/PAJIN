from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities.domain_projection import (
    CapabilityDomainInventoryProjection,
    RegisteredCapabilityDomainClassification,
    registered_capability_domain_inventory_projection,
)
from pajin.capabilities.existing import (
    ExistingModeCapabilityBundle,
    existing_mode_capability_bundle,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity
from pajin.capabilities.pentest_recon import (
    PentestReconCapabilityBundle,
    pentest_recon_capability_bundle,
)
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryError,
    DomainWorkerBoundaryProfileRegistry,
    DomainWorkerDeploymentBinding,
    DomainWorkerDeploymentRegistry,
    RegisteredDomainWorkerBoundaryProfile,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    build_domain_worker_deployment_registry,
    register_domain_worker_deployment_binding,
    registered_domain_worker_boundary_profiles,
    resolve_domain_worker_deployment_binding,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSTrustPolicy,
)
from pajin.domain.security_domain import SecurityDomain
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
_DEPLOYMENT_ID = "deployment.domain-worker.test"
_WORKER_SUBJECT = "worker:web-recon"
_POLICY_ID = "worker-mtls-policy_0123456789abcdef0123456789abcdef"
_SPKI = "1" * 64

_PROFILE_FALSE_MARKERS = (
    "domainOnlySelectionAuthorized",
    "toolMetadataSelectionAuthorized",
    "networkAccessAuthorized",
    "filesystemAccessAuthorized",
    "credentialUseAuthorized",
    "deviceAccessAuthorized",
    "evidenceMutationAuthorized",
    "workerSelectionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_BINDING_FALSE_MARKERS = (
    "currentActivationBound",
    "campaignAuthorityBound",
    "graphDecisionBound",
    "approvalSatisfied",
    "permitBound",
    "gatewayDispatchAuthorized",
    "profileConformanceVerified",
    "workerSelectionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)


def _seed(label: str) -> bytes:
    return sha256(f"domain-worker:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"domain-worker.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


def _tools() -> ToolRegistry:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
        HTTPGetTool(),
        demo_mcp_tool(),
    ):
        tools.register(tool)
    return tools


@pytest.fixture
def source_bundles() -> tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle]:
    tools = _tools()
    return (
        existing_mode_capability_bundle(tools, include_registered_mcp=True),
        pentest_recon_capability_bundle(tools),
    )


@pytest.fixture
def projection(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> CapabilityDomainInventoryProjection:
    existing, pentest = source_bundles
    return registered_capability_domain_inventory_projection(
        existing_bundle=existing,
        pentest_recon_bundle=pentest,
    )


@pytest.fixture
def signed_pentest_release(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
) -> tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle]:
    _, pentest = source_bundles
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="domain-worker.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="domain-worker.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    review = CapabilityReviewStatement(
        capability=pentest.capability(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"domain-worker-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(days=2),
        expiresAt=NOW + timedelta(days=5),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=pentest.capability(),
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(days=1),
    )
    signed_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=pentest.definitions,
        authorities=pentest.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    return lifecycle, signed_bundle


def _worker_policy(*, subject: str = _WORKER_SUBJECT, spki: str = _SPKI) -> WorkerMTLSTrustPolicy:
    return WorkerMTLSTrustPolicy(
        policy_id=_POLICY_ID,
        bindings=(
            WorkerCertificateBinding(
                principal_subject=subject,
                certificate_spki_sha256=spki,
            ),
        ),
    )


def _classification(
    projection: CapabilityDomainInventoryProjection,
    capability_id: str = "pajin.pentest.http-get-recon",
) -> RegisteredCapabilityDomainClassification:
    return next(
        item for item in projection.bindings if item.capability.capability_id == capability_id
    )


def _profile(domain: SecurityDomain) -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is domain
    )


def _binding(
    *,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
    policy: WorkerMTLSTrustPolicy | None = None,
) -> DomainWorkerDeploymentBinding:
    existing, pentest = source_bundles
    lifecycle, signed_bundle = signed_pentest_release
    classification = _classification(projection)
    return register_domain_worker_deployment_binding(
        deployment_id=_DEPLOYMENT_ID,
        lifecycle=lifecycle,
        release=signed_bundle.release.statement.reference(),
        capability_domain_classification=classification.reference(),
        worker_profile=_profile(SecurityDomain.WEB).reference(),
        worker_mtls_policy=policy or _worker_policy(),
        worker_subject=_WORKER_SUBJECT,
        existing_bundle=existing,
        pentest_recon_bundle=pentest,
    )


def test_registers_exact_nine_code_owned_minimum_profiles() -> None:
    registry = registered_domain_worker_boundary_profiles()

    assert tuple(item.domain_classification.domain for item in registry.profiles) == tuple(
        SecurityDomain
    )
    assert registry.profile_count == 9
    assert len(registry.registry_digest) == 64
    assert registry.code_owned is True
    assert registry.profile_selection_authorized is False
    assert registry.runtime_support_asserted is False
    assert registry.execution_authorized is False
    assert DomainWorkerBoundaryProfileRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    ) == registry


def test_profiles_encode_arch002_minimum_boundaries() -> None:
    profiles = {
        item.domain_classification.domain: item
        for item in registered_domain_worker_boundary_profiles().profiles
    }

    assert profiles[SecurityDomain.WEB].network_boundary is WorkerNetworkBoundary.BOUNDED_EGRESS
    assert (
        profiles[SecurityDomain.NETWORK].network_boundary
        is WorkerNetworkBoundary.EXACT_HOST_PROTOCOL_PORT
    )
    assert profiles[SecurityDomain.NETWORK].protocol_privilege_review_required is True
    assert (
        profiles[SecurityDomain.SYSTEM].runtime_boundary
        is WorkerRuntimeBoundary.AUTHENTICATED_NON_ROOT_AGENT
    )
    assert (
        profiles[SecurityDomain.APPLICATION].filesystem_boundary
        is WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
    )
    assert profiles[SecurityDomain.MOBILE].runtime_boundary is WorkerRuntimeBoundary.DEVICE_BOUND
    assert (
        profiles[SecurityDomain.CLOUD].credential_boundary
        is WorkerCredentialBoundary.EPHEMERAL_LEASE
    )
    assert profiles[SecurityDomain.AI].required_budget_dimensions == (
        "cost",
        "request-count",
        "token-count",
    )
    assert (
        profiles[SecurityDomain.CRYPTOGRAPHY].network_boundary
        is WorkerNetworkBoundary.DISABLED_BY_DEFAULT
    )
    assert (
        profiles[SecurityDomain.FORENSICS].filesystem_boundary
        is WorkerFilesystemBoundary.IMMUTABLE_EVIDENCE
    )
    assert profiles[SecurityDomain.FORENSICS].provenance_preservation_required is True


@pytest.mark.parametrize("domain", tuple(SecurityDomain))
def test_profile_resolution_is_exact_and_grants_no_authority(domain: SecurityDomain) -> None:
    source = _profile(domain)
    resolved = resolve_registered_domain_worker_boundary_profile(source.reference())
    payload = resolved.model_dump(mode="json", by_alias=True)

    assert resolved == source
    assert resolved is not source
    assert all(payload[alias] is False for alias in _PROFILE_FALSE_MARKERS)


def test_profile_reference_substitution_fails_closed() -> None:
    source = _profile(SecurityDomain.WEB).reference()
    wrong_digest = source.model_copy(update={"profile_digest": "0" * 64})
    wrong_domain = source.model_copy(
        update={"domain_classification": _profile(SecurityDomain.NETWORK).domain_classification}
    )

    for reference in (wrong_digest, wrong_domain):
        with pytest.raises(DomainWorkerBoundaryError, match="not registered exactly"):
            resolve_registered_domain_worker_boundary_profile(reference)


def test_profile_catalog_rejects_content_drift_and_reordering() -> None:
    payload = registered_domain_worker_boundary_profiles().model_dump(
        mode="json",
        by_alias=True,
    )

    changed = deepcopy(payload)
    changed["profiles"][0]["networkBoundary"] = "disabled-by-default"
    changed["profiles"][0]["profileDigest"] = ""
    changed["registryDigest"] = ""
    with pytest.raises(ValidationError, match="differs from code authority"):
        DomainWorkerBoundaryProfileRegistry.model_validate(changed)

    reordered = deepcopy(payload)
    reordered["profiles"] = list(reversed(reordered["profiles"]))
    reordered["registryDigest"] = ""
    with pytest.raises(ValidationError, match="differs from code authority"):
        DomainWorkerBoundaryProfileRegistry.model_validate(reordered)


@pytest.mark.parametrize("alias", _PROFILE_FALSE_MARKERS)
@pytest.mark.parametrize("escalated", (True, 1, "false"))
def test_profile_authority_markers_fail_closed(alias: str, escalated: object) -> None:
    payload = _profile(SecurityDomain.WEB).model_dump(mode="json", by_alias=True)
    payload[alias] = escalated
    payload["profileDigest"] = ""

    with pytest.raises(ValidationError):
        type(_profile(SecurityDomain.WEB)).model_validate(payload)


def test_binding_pins_verified_release_profile_and_worker_identity_without_execution(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    binding = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
    )
    _, signed_bundle = signed_pentest_release
    payload = binding.model_dump(mode="json", by_alias=True)

    assert binding.capability_release == signed_bundle.release.statement.reference()
    assert binding.capability == signed_bundle.release.statement.capability
    assert binding.worker_profile == _profile(SecurityDomain.WEB).reference()
    assert binding.worker_identity == _worker_policy().bindings[0]
    assert binding.signed_release_verified is True
    assert binding.capability_domain_classification_verified is True
    assert binding.worker_identity_policy_verified is True
    assert all(payload[alias] is False for alias in _BINDING_FALSE_MARKERS)
    assert len(binding.release_bundle_digest) == 64
    assert len(binding.worker_mtls_policy_digest) == 64
    assert DomainWorkerDeploymentBinding.model_validate(payload) == binding


def test_binding_rejects_unregistered_release(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    existing, pentest = source_bundles
    lifecycle, signed_bundle = signed_pentest_release
    classification = _classification(projection)
    unregistered = CapabilityReleaseRef(
        releaseId=f"capability-release_{'0' * 64}",
        releaseDigest="0" * 64,
    )

    with pytest.raises(DomainWorkerBoundaryError, match="not signed and registered exactly"):
        register_domain_worker_deployment_binding(
            deployment_id=_DEPLOYMENT_ID,
            lifecycle=lifecycle,
            release=unregistered,
            capability_domain_classification=classification.reference(),
            worker_profile=_profile(SecurityDomain.WEB).reference(),
            worker_mtls_policy=_worker_policy(),
            worker_subject=_WORKER_SUBJECT,
            existing_bundle=existing,
            pentest_recon_bundle=pentest,
        )
    assert signed_bundle.release.statement.reference() != unregistered


def test_binding_rejects_domain_or_capability_substitution(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    existing, pentest = source_bundles
    lifecycle, signed_bundle = signed_pentest_release
    recon = _classification(projection)
    crypto = _classification(projection, "pajin.ctf.crypto-single-byte-xor")

    for classification, profile in (
        (recon, _profile(SecurityDomain.AI)),
        (crypto, _profile(SecurityDomain.CRYPTOGRAPHY)),
    ):
        with pytest.raises(DomainWorkerBoundaryError, match="release, Capability, and profile"):
            register_domain_worker_deployment_binding(
                deployment_id=_DEPLOYMENT_ID,
                lifecycle=lifecycle,
                release=signed_bundle.release.statement.reference(),
                capability_domain_classification=classification.reference(),
                worker_profile=profile.reference(),
                worker_mtls_policy=_worker_policy(),
                worker_subject=_WORKER_SUBJECT,
                existing_bundle=existing,
                pentest_recon_bundle=pentest,
            )


def test_binding_rejects_missing_or_substituted_worker_identity(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    existing, pentest = source_bundles
    lifecycle, signed_bundle = signed_pentest_release

    with pytest.raises(DomainWorkerBoundaryError, match="not bound"):
        register_domain_worker_deployment_binding(
            deployment_id=_DEPLOYMENT_ID,
            lifecycle=lifecycle,
            release=signed_bundle.release.statement.reference(),
            capability_domain_classification=_classification(projection).reference(),
            worker_profile=_profile(SecurityDomain.WEB).reference(),
            worker_mtls_policy=_worker_policy(subject="worker:other"),
            worker_subject=_WORKER_SUBJECT,
            existing_bundle=existing,
            pentest_recon_bundle=pentest,
        )


def test_binding_rejects_noncanonical_worker_policy_copy(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    existing, pentest = source_bundles
    lifecycle, signed_bundle = signed_pentest_release
    policy = _worker_policy()
    drifted = policy.model_copy(update={"bindings": (policy.bindings[0], policy.bindings[0])})

    with pytest.raises(DomainWorkerBoundaryError, match="policy is not canonical"):
        register_domain_worker_deployment_binding(
            deployment_id=_DEPLOYMENT_ID,
            lifecycle=lifecycle,
            release=signed_bundle.release.statement.reference(),
            capability_domain_classification=_classification(projection).reference(),
            worker_profile=_profile(SecurityDomain.WEB).reference(),
            worker_mtls_policy=drifted,
            worker_subject=_WORKER_SUBJECT,
            existing_bundle=existing,
            pentest_recon_bundle=pentest,
        )


def test_policy_or_certificate_substitution_changes_exact_binding(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    first = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
    )
    second = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
        policy=_worker_policy(spki="2" * 64),
    )

    assert first.worker_mtls_policy_digest != second.worker_mtls_policy_digest
    assert first.worker_identity != second.worker_identity
    assert first.binding_digest != second.binding_digest


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
@pytest.mark.parametrize("escalated", (True, 1, "false"))
def test_binding_authority_markers_fail_closed(
    alias: str,
    escalated: object,
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    payload = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
    ).model_dump(mode="json", by_alias=True)
    payload[alias] = escalated
    payload["bindingId"] = ""
    payload["bindingDigest"] = ""

    with pytest.raises(ValidationError):
        DomainWorkerDeploymentBinding.model_validate(payload)


def test_deployment_registry_resolves_only_exact_binding_reference(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    binding = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
    )
    registry = build_domain_worker_deployment_registry(
        deployment_id=_DEPLOYMENT_ID,
        bindings=(binding,),
    )
    resolved = resolve_domain_worker_deployment_binding(
        binding.reference(),
        registry=registry,
    )

    assert resolved == binding
    assert resolved is not binding
    assert registry.profile_conformance_authority_included is False
    assert registry.current_activation_authority_included is False
    assert registry.permit_issuance_authorized is False
    assert registry.gateway_dispatch_authorized is False
    assert registry.execution_authorized is False
    assert DomainWorkerDeploymentRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    ) == registry

    wrong = binding.reference().model_copy(update={"binding_digest": "0" * 64})
    with pytest.raises(DomainWorkerBoundaryError, match="not registered exactly"):
        resolve_domain_worker_deployment_binding(wrong, registry=registry)


def test_deployment_registry_rejects_cross_deployment_or_duplicate_membership(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    binding = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
    )

    with pytest.raises(ValidationError, match="bindings differ"):
        DomainWorkerDeploymentRegistry(
            deploymentId="deployment:other",
            profileRegistryDigest=registered_domain_worker_boundary_profiles().registry_digest,
            bindings=(binding,),
        )
    with pytest.raises(ValidationError, match="bindings differ"):
        DomainWorkerDeploymentRegistry(
            deploymentId=_DEPLOYMENT_ID,
            profileRegistryDigest=registered_domain_worker_boundary_profiles().registry_digest,
            bindings=(binding, binding),
        )


def test_domain_or_tool_metadata_cannot_replace_exact_deployment_inputs(
    source_bundles: tuple[ExistingModeCapabilityBundle, PentestReconCapabilityBundle],
    projection: CapabilityDomainInventoryProjection,
    signed_pentest_release: tuple[CapabilityLifecycleRegistry, CapabilityReleaseBundle],
) -> None:
    payload = _binding(
        source_bundles=source_bundles,
        projection=projection,
        signed_pentest_release=signed_pentest_release,
    ).model_dump(mode="json", by_alias=True)
    for alias, value in (
        ("domain", "web"),
        ("toolCategory", "network"),
        ("workerId", "worker:any"),
        ("scope", {"targets": ["example.test"]}),
        ("permit", "permit:any"),
    ):
        changed = deepcopy(payload)
        changed[alias] = value
        changed["bindingId"] = ""
        changed["bindingDigest"] = ""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            DomainWorkerDeploymentBinding.model_validate(changed)
