from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityAuthorityRole,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityMaturity,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.pentest_recon import (
    PentestReconCapabilityActivation,
    activate_pentest_recon_capability,
    pentest_recon_capability_bundle,
    registered_pentest_recon_capability_definition,
)
from pajin.capabilities.web_discovery import (
    WebReadOnlyDiscoveryBinding,
    WebReadOnlyDiscoveryError,
    WebReadOnlyDiscoveryPreparation,
    prepare_web_read_only_discovery,
    registered_web_read_only_discovery_binding,
    resolve_web_read_only_discovery_binding,
)
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.discovery import (
    http_route_surface_locator,
    http_surface_locator,
    registered_web_http_operation_locator_registry,
    typed_web_http_operation_surface,
)
from pajin.domain.security_domain import SecurityDomain
from pajin.runtime.worker import NetworkMode
from pajin.tools.base import ToolRegistry
from pajin.tools.http import MAX_HTTP_GET_RESPONSE_BYTES, HTTPGetTool

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

_BINDING_FALSE_ALIASES = (
    "uriTemplateMaterializationAvailable",
    "redirectFollowAuthorized",
    "ambientCredentialUseAuthorized",
    "domainMetadataAuthority",
    "surfaceMetadataAuthority",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "workerSelectionAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_PREPARATION_FALSE_ALIASES = (
    "workerJobMaterialized",
    "egressPolicyMaterialized",
    "discoveryObservationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "scopeExpansionAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "executionAuthorized",
)


def _seed(label: str) -> bytes:
    return sha256(f"web-read-only-discovery:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"web-discovery.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


@lru_cache(maxsize=1)
def _signed_activation() -> tuple[PentestReconCapabilityActivation, CapabilityReleaseRef]:
    tools = ToolRegistry()
    tools.register(HTTPGetTool())
    capability_bundle = pentest_recon_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="web-discovery.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="web-discovery.reviewer",
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
        capability=capability_bundle.capability(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"web-read-only-discovery-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(days=2),
        expiresAt=NOW + timedelta(days=5),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=capability_bundle.capability(),
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
        definitions=capability_bundle.definitions,
        authorities=capability_bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    activation = activate_pentest_recon_capability(
        bundle=capability_bundle,
        lifecycle=lifecycle,
        release=signed_bundle.release.statement.reference(),
    )
    return activation, signed_bundle.release.statement.reference()


def _get_surface():
    return typed_web_http_operation_surface(
        locator=http_surface_locator(
            url="https://api.example.test/v1/health",
            method="get",
        )
    )


def _route_surface():
    return typed_web_http_operation_surface(
        locator=http_route_surface_locator(
            base_url="https://api.example.test/v1",
            path_template="/users/{user_id}",
            method="GET",
        )
    )


@lru_cache(maxsize=1)
def _preparation() -> WebReadOnlyDiscoveryPreparation:
    activation, release = _signed_activation()
    return prepare_web_read_only_discovery(
        activation=activation,
        release=release,
        surface=_get_surface(),
        request_id="web-discovery-request-1",
        agent_id="worker.web-discovery",
    )


def test_binding_reuses_exact_cap_002_and_egress_only_worker_boundary() -> None:
    binding = registered_web_read_only_discovery_binding()
    definition = registered_pentest_recon_capability_definition()
    worker = resolve_registered_domain_worker_boundary_profile(binding.worker_profile)
    locator_registry = registered_web_http_operation_locator_registry()

    assert binding.capability.capability == definition.reference()
    assert binding.capability_domain_classification.capability == definition.reference()
    assert (
        binding.capability_domain_classification.domain_classification.domain is SecurityDomain.WEB
    )
    assert binding.locator_registry == locator_registry.reference()
    assert binding.supported_locator == locator_registry.locators[0].reference()
    assert binding.supported_locator.locator_kind == "http-endpoint"
    assert binding.method == "GET"
    assert binding.side_effect_class.value == "read-only"
    assert binding.request_units == 1
    assert binding.max_response_bytes == MAX_HTTP_GET_RESPONSE_BYTES
    assert worker.network_boundary is WorkerNetworkBoundary.BOUNDED_EGRESS
    assert worker.filesystem_boundary is WorkerFilesystemBoundary.NO_HOST_ACCESS
    assert worker.credential_boundary is WorkerCredentialBoundary.NONE
    assert worker.runtime_boundary is WorkerRuntimeBoundary.ISOLATED_NON_ROOT
    assert binding.gateway_egress_required is True
    assert binding.worker_deployment_binding_required is True
    assert binding.worker_direct_mtls_required is True
    assert (
        WebReadOnlyDiscoveryBinding.model_validate(binding.model_dump(mode="json", by_alias=True))
        == binding
    )


def test_binding_exact_reference_resolves_to_detached_copy() -> None:
    binding = registered_web_read_only_discovery_binding()
    resolved = resolve_web_read_only_discovery_binding(binding.reference())

    assert resolved == binding
    assert resolved is not binding


def test_binding_reference_digest_substitution_fails_closed() -> None:
    binding = registered_web_read_only_discovery_binding()

    with pytest.raises(WebReadOnlyDiscoveryError, match="not registered exactly"):
        resolve_web_read_only_discovery_binding(
            binding.reference().model_copy(update={"binding_digest": "0" * 64})
        )


def test_signed_activation_prepares_exact_get_without_granting_egress() -> None:
    activation, release = _signed_activation()
    surface = _get_surface()
    preparation = prepare_web_read_only_discovery(
        activation=activation,
        release=release,
        surface=surface,
        request_id="web-discovery-request-1",
        agent_id="worker.web-discovery",
    )
    request = preparation.prepared_action.request
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    pre_gateway_job = executor.prepare(request)

    assert preparation.state == "prepared-not-authorized"
    assert preparation.surface == surface
    assert preparation.surface is not surface
    assert request.request_id == "web-discovery-request-1"
    assert request.agent_id == "worker.web-discovery"
    assert request.tool_id == "http.get"
    assert request.target == "https://api.example.test/v1/health"
    assert request.method == "GET"
    assert request.arguments == {}
    assert preparation.prepared_action.release == release
    assert preparation.capability_prepared is True
    assert preparation.gateway_egress_required is True
    assert pre_gateway_job.network is NetworkMode.NONE
    assert pre_gateway_job.egress_policy is None
    assert preparation.preparation_id == (
        f"web-discovery-preparation_{preparation.preparation_digest}"
    )
    assert (
        WebReadOnlyDiscoveryPreparation.model_validate(
            preparation.model_dump(mode="json", by_alias=True)
        )
        == preparation
    )


def test_uri_template_and_non_get_surfaces_cannot_be_promoted_to_execution() -> None:
    activation, release = _signed_activation()

    with pytest.raises(WebReadOnlyDiscoveryError, match="does not materialize URI-template"):
        prepare_web_read_only_discovery(
            activation=activation,
            release=release,
            surface=_route_surface(),
            request_id="web-discovery-route",
            agent_id="worker.web-discovery",
        )

    post_surface = typed_web_http_operation_surface(
        locator=http_surface_locator(
            url="https://api.example.test/v1/health",
            method="POST",
        )
    )
    with pytest.raises(WebReadOnlyDiscoveryError, match="only an exact concrete GET"):
        prepare_web_read_only_discovery(
            activation=activation,
            release=release,
            surface=post_surface,
            request_id="web-discovery-post",
            agent_id="worker.web-discovery",
        )


def test_wrong_release_and_noncanonical_surface_fail_before_preparation() -> None:
    activation, release = _signed_activation()

    with pytest.raises(WebReadOnlyDiscoveryError, match="CAP-002 preparation failed closed"):
        prepare_web_read_only_discovery(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            surface=_get_surface(),
            request_id="web-discovery-wrong-release",
            agent_id="worker.web-discovery",
        )

    forged_surface = _get_surface().model_copy(update={"execution_authorized": True})
    with pytest.raises(WebReadOnlyDiscoveryError, match="Surface is not canonical"):
        prepare_web_read_only_discovery(
            activation=activation,
            release=release,
            surface=forged_surface,
            request_id="web-discovery-forged-surface",
            agent_id="worker.web-discovery",
        )


def test_binding_and_preparation_explicitly_carry_no_derived_authority() -> None:
    binding = registered_web_read_only_discovery_binding()
    preparation = _preparation()
    binding_payload = binding.model_dump(mode="json", by_alias=True)
    preparation_payload = preparation.model_dump(mode="json", by_alias=True)

    assert all(binding_payload[alias] is False for alias in _BINDING_FALSE_ALIASES)
    assert all(preparation_payload[alias] is False for alias in _PREPARATION_FALSE_ALIASES)
    assert {
        "campaign",
        "scope",
        "approval",
        "permit",
        "worker",
        "observation",
        "evidence",
        "finding",
    }.isdisjoint(WebReadOnlyDiscoveryPreparation.model_fields)


@pytest.mark.parametrize("alias", _BINDING_FALSE_ALIASES)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_web_read_only_discovery_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        WebReadOnlyDiscoveryBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        WebReadOnlyDiscoveryBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _PREPARATION_FALSE_ALIASES)
def test_preparation_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = _preparation().model_dump(mode="json", by_alias=True)
    payload[alias] = True
    with pytest.raises(ValidationError):
        WebReadOnlyDiscoveryPreparation.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        WebReadOnlyDiscoveryPreparation.model_validate(payload)


@pytest.mark.parametrize(
    ("parent", "key", "value", "match"),
    (
        (None, "method", "HEAD", "Input should be 'GET'"),
        (None, "maxResponseBytes", 8192, "Input should be 4096"),
        ("capability", "authoritySetDigest", "0" * 64, "code authority"),
        ("capabilityDomainClassification", "classificationDigest", "0" * 64, "code authority"),
        ("workerProfile", "profileDigest", "0" * 64, "code authority"),
        ("supportedLocator", "locatorDigest", "0" * 64, "code authority"),
        (None, "bindingDigest", "0" * 64, "digest differs"),
    ),
)
def test_binding_rejects_capability_domain_worker_locator_and_budget_drift(
    parent: str | None,
    key: str,
    value: object,
    match: str,
) -> None:
    payload = deepcopy(
        registered_web_read_only_discovery_binding().model_dump(
            mode="json",
            by_alias=True,
        )
    )
    target = payload if parent is None else payload[parent]
    target[key] = value

    with pytest.raises(ValidationError, match=match):
        WebReadOnlyDiscoveryBinding.model_validate(payload)


def test_binding_rejects_injected_tool_or_scope_mapping() -> None:
    for field, value in (
        ("toolId", "http.get"),
        ("scope", {"allow": ["https://example.test/**"]}),
        ("workerId", "worker.web"),
    ):
        payload = registered_web_read_only_discovery_binding().model_dump(
            mode="json",
            by_alias=True,
        )
        payload[field] = value
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            WebReadOnlyDiscoveryBinding.model_validate(payload)


def test_preparation_rejects_request_surface_identity_and_digest_drift() -> None:
    original = _preparation().model_dump(mode="json", by_alias=True)
    mutations = (
        ("preparedAction", "requestDigest", "0" * 64),
        ("preparedAction", "normalizedParametersDigest", "0" * 64),
        ("surface", "surfaceDigest", "0" * 64),
        (None, "preparationDigest", "0" * 64),
        (None, "preparationId", "web-discovery-preparation_" + "0" * 64),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            WebReadOnlyDiscoveryPreparation.model_validate(payload)
