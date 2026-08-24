from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities.authorities import CapabilityAuthorityRole, CapabilityOracleDecision
from pajin.capabilities.cloud_inventory import (
    CLOUD_CREDENTIAL_BINDING,
    CLOUD_READ_ONLY_CAPABILITY_ID,
    CLOUD_READ_ONLY_TOOL_ID,
    BoundedCloudReadOnlyProviderAdapter,
    CloudCredentialLeaseReference,
    CloudProviderReadRequest,
    CloudReadOnlyCapabilityActivation,
    CloudReadOnlyCapabilityError,
    CloudReadOnlyInventoryPolicyBinding,
    CloudReadOnlyInventoryPolicyPreparation,
    CloudReadOnlyInventoryPolicyTool,
    CloudReadOnlyOperation,
    CloudReadOnlyProviderAdapterDefinition,
    CloudReadOnlyProviderRoute,
    activate_cloud_read_only_capability,
    bind_cloud_credential_lease_reference,
    cloud_credential_lease_scope,
    cloud_read_only_capability_bundle,
    cloud_surface_scope_target,
    prepare_cloud_read_only_inventory_policy,
    registered_cloud_read_only_capability_definition,
    registered_cloud_read_only_capability_domain_classification,
    registered_cloud_read_only_inventory_policy_binding,
    resolve_cloud_read_only_capability_domain_classification,
    resolve_cloud_read_only_inventory_policy_binding,
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
from pajin.capabilities.models import CapabilityMaturity, CapabilitySideEffectClass
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.discovery import (
    CloudAccountResourceSurface,
    CloudIAMObjectKind,
    cloud_account_surface_locator,
    cloud_iam_surface_locator,
    cloud_resource_surface_locator,
    typed_cloud_account_resource_surface,
)
from pajin.domain.models import CampaignManifest, ToolResult, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretLeaseStatus
from pajin.tools.base import ToolRegistry

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
ENDPOINT = "https://api.cloud.example.test"
AUDIENCE = "worker.cloud-read-only"
SECRET_REF = "secret://cloud/provider-read"
SECRET_VALUE = "test-cloud-provider-credential"

_BINDING_FALSE_MARKERS = (
    "ambientCredentialUseAuthorized",
    "providerSelectionAuthorized",
    "policyMutationAuthorized",
    "iamMutationAuthorized",
    "containerWriteAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "observationProductionAuthorized",
    "evidenceSealingAuthorized",
    "graphAdmissionAuthorized",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_PREPARATION_FALSE_MARKERS = (
    "providerRuntimeAdapterAvailable",
    "leaseIdEmbedded",
    "credentialMaterialized",
    "credentialUseAuthorized",
    "providerInvoked",
    "policyMutationAuthorized",
    "iamMutationAuthorized",
    "containerWriteAuthorized",
    "workerJobMaterialized",
    "egressPolicyMaterialized",
    "networkRequestPerformed",
    "observationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "executionAuthorized",
)


def _seed(label: str) -> bytes:
    return sha256(f"cloud-read-only:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"cloud-read-only.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


def _activation() -> tuple[CloudReadOnlyCapabilityActivation, CapabilityReleaseRef]:
    tools = ToolRegistry()
    tools.register(CloudReadOnlyInventoryPolicyTool())
    bundle = cloud_read_only_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="cloud-read-only.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="cloud-read-only.reviewer",
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
        capability=bundle.capability(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"cloud-read-only-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(days=2),
        expiresAt=NOW + timedelta(days=5),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=bundle.capability(),
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
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    release_ref = signed_bundle.release.statement.reference()
    return (
        activate_cloud_read_only_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


def _account():
    return cloud_account_surface_locator(
        provider_id="aws",
        provider_partition="aws",
        account_id="123456789012",
    )


def _resource_surface() -> CloudAccountResourceSurface:
    return typed_cloud_account_resource_surface(
        locator=cloud_resource_surface_locator(
            parent=_account(),
            service_id="s3",
            location_id="ap-northeast-2",
            resource_type="bucket",
            resource_id="pajin-artifacts-123456789012",
        )
    )


def _iam_surface() -> CloudAccountResourceSurface:
    return typed_cloud_account_resource_surface(
        locator=cloud_iam_surface_locator(
            parent=_account(),
            iam_object_kind=CloudIAMObjectKind.ROLE,
            iam_id="role/pajin-read-only",
        )
    )


def _route(
    surface: CloudAccountResourceSurface,
    operation: CloudReadOnlyOperation,
    *,
    target: str | None = None,
) -> CloudReadOnlyProviderRoute:
    suffix = "inventory" if operation is CloudReadOnlyOperation.INVENTORY else "policy"
    return CloudReadOnlyProviderRoute(
        operation=operation,
        surface=surface.reference(),
        target=target or f"{ENDPOINT}/v1/{suffix}/{surface.surface_id}",
        maxResponseBytes=131_072,
    )


def _adapter(
    surface: CloudAccountResourceSurface,
    operation: CloudReadOnlyOperation = CloudReadOnlyOperation.INVENTORY,
    *,
    endpoint: str = ENDPOINT,
    target: str | None = None,
) -> BoundedCloudReadOnlyProviderAdapter:
    definition = CloudReadOnlyProviderAdapterDefinition(
        adapterId="pajin.cloud-provider.test-read-only",
        providerId="aws",
        providerPartition="aws",
        endpointOrigin=endpoint,
        credentialAudience=AUDIENCE,
        maxCredentialTtlSeconds=45,
        maxRuntimeSeconds=30,
        routes=(_route(surface, operation, target=target),),
    )
    return BoundedCloudReadOnlyProviderAdapter(definition)


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    surface: CloudAccountResourceSurface,
    adapter: BoundedCloudReadOnlyProviderAdapter,
    deny: list[str] | None = None,
    include_surface: bool = True,
    include_provider: bool = True,
    allow_get: bool = True,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    allow: list[str] = []
    if include_surface:
        allow.append(cloud_surface_scope_target(surface))
    if include_provider:
        allow.append(adapter.definition.routes[0].target)
    payload["spec"]["scope"] = {
        "allow": allow or ["https://unrelated.example.test/"],
        "deny": deny or [],
    }
    methods = set(payload["spec"]["rulesOfEngagement"]["allowedMethods"])
    if allow_get:
        methods.add("GET")
    else:
        methods.discard("GET")
    payload["spec"]["rulesOfEngagement"]["allowedMethods"] = sorted(methods)
    return CampaignManifest.model_validate(payload)


def _broker_lease(
    campaign: CampaignManifest,
    adapter: BoundedCloudReadOnlyProviderAdapter,
    *,
    audience: str = AUDIENCE,
    scope: str | None = None,
    ttl_seconds: int = 30,
    max_uses: int = 1,
) -> tuple[SecretBroker, SecretLease]:
    broker = SecretBroker(clock=lambda: NOW)
    broker.register(SECRET_REF, SECRET_VALUE)
    lease = broker.issue(
        SECRET_REF,
        audience=audience,
        binding=adapter.definition.credential_binding,
        scope=scope or cloud_credential_lease_scope(campaign),
        ttl_seconds=ttl_seconds,
        max_uses=max_uses,
    )
    return broker, lease


def _prepare(
    sample_campaign: CampaignManifest,
    *,
    surface: CloudAccountResourceSurface | None = None,
    operation: CloudReadOnlyOperation = CloudReadOnlyOperation.INVENTORY,
) -> CloudReadOnlyInventoryPolicyPreparation:
    selected_surface = surface or _resource_surface()
    adapter = _adapter(selected_surface, operation)
    campaign = _campaign(sample_campaign, surface=selected_surface, adapter=adapter)
    activation, release = _activation()
    broker, lease = _broker_lease(campaign, adapter)
    return prepare_cloud_read_only_inventory_policy(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=selected_surface,
        operation=operation,
        provider_adapter=adapter,
        secret_broker=broker,
        credential_lease=lease,
        evaluated_at=NOW,
        request_id="tool_cloud_read_only_prepare",
        agent_id="agent:cloud-read-only",
    )


def test_capability_binding_pins_cloud_cap_002_and_worker_boundary() -> None:
    definition = registered_cloud_read_only_capability_definition()
    binding = registered_cloud_read_only_inventory_policy_binding()
    tools = ToolRegistry()
    tools.register(CloudReadOnlyInventoryPolicyTool())
    bundle = cloud_read_only_capability_bundle(tools)
    worker = resolve_registered_domain_worker_boundary_profile(binding.worker_profile)

    assert definition.capability_id == CLOUD_READ_ONLY_CAPABILITY_ID
    assert definition.supported_surface_types == (
        "cloud-account",
        "cloud-container",
        "cloud-iam",
        "cloud-project",
        "cloud-resource",
    )
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is True
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert binding.capability == bundle.capability()
    assert worker.network_boundary is WorkerNetworkBoundary.BOUNDED_EGRESS
    assert worker.filesystem_boundary is WorkerFilesystemBoundary.NO_HOST_ACCESS
    assert worker.credential_boundary is WorkerCredentialBoundary.EPHEMERAL_LEASE
    assert worker.runtime_boundary is WorkerRuntimeBoundary.ISOLATED_NON_ROOT
    assert worker.required_identity_dimensions == (
        "account-or-project",
        "credential-lease",
        "resource",
    )
    assert worker.required_budget_dimensions == (
        "credential-ttl",
        "request-count",
        "runtime",
    )
    payload = binding.model_dump(mode="json", by_alias=True)
    assert all(payload[alias] is False for alias in _BINDING_FALSE_MARKERS)
    classification = registered_cloud_read_only_capability_domain_classification()
    assert classification.domain_classification.domain is SecurityDomain.CLOUD
    assert (
        resolve_cloud_read_only_capability_domain_classification(classification.reference())
        == classification
    )
    assert resolve_cloud_read_only_inventory_policy_binding(binding.reference()) == binding


def test_bounded_adapter_builds_secret_free_exact_get_request(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    broker, lease = _broker_lease(campaign, adapter)
    reference = bind_cloud_credential_lease_reference(
        broker=broker,
        lease=lease,
        campaign=campaign,
        provider_adapter=adapter.definition,
        evaluated_at=NOW,
    )
    request = adapter.prepare_request(
        surface=surface,
        operation=CloudReadOnlyOperation.INVENTORY,
        credential_lease=reference,
    )
    payload = request.model_dump(mode="json", by_alias=True)

    assert request.method == "GET"
    assert request.surface == surface.reference()
    assert request.target == adapter.definition.routes[0].target
    assert request.budget.request_count == 1
    assert request.budget.provider_write_requests == 0
    assert request.budget.credential_ttl_seconds == 45
    assert lease.lease_id not in str(payload)
    assert SECRET_VALUE not in str(payload)
    assert SECRET_REF not in str(payload)
    assert reference.lease_id_fingerprint == sha256(lease.lease_id.encode()).hexdigest()
    assert reference.lease_id_embedded is False
    assert reference.credential_material_embedded is False
    assert CloudProviderReadRequest.model_validate(payload) == request


def test_signed_preparation_binds_scope_adapter_lease_and_capability_without_dispatch(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    request = preparation.prepared_action.request
    payload = preparation.model_dump(mode="json", by_alias=True)

    assert preparation.state == "prepared-not-authorized"
    assert preparation.operation is CloudReadOnlyOperation.INVENTORY
    assert preparation.matched_surface_allow_rule == cloud_surface_scope_target(preparation.surface)
    assert preparation.matched_provider_allow_rule == preparation.provider_request.target
    assert preparation.credential_lease.scope == _credential_scope_from_preparation(preparation)
    assert request.method == "GET"
    assert request.target == preparation.provider_request.target
    assert request.arguments == preparation.provider_request.model_dump(mode="json", by_alias=True)
    assert all(payload[alias] is False for alias in _PREPARATION_FALSE_MARKERS)
    assert "leaseId" not in payload["credentialLease"]
    assert "leaseId" not in payload["providerRequest"]["credentialLease"]
    assert SECRET_VALUE not in str(payload)
    assert preparation.preparation_id == (
        f"cloud-read-only-preparation_{preparation.preparation_digest}"
    )
    assert CloudReadOnlyInventoryPolicyPreparation.model_validate(payload) == preparation


def _credential_scope_from_preparation(
    preparation: CloudReadOnlyInventoryPolicyPreparation,
) -> str:
    return f"campaign-cloud:{preparation.campaign_scope.campaign_digest}"


def test_policy_read_requires_exact_iam_surface(sample_campaign: CampaignManifest) -> None:
    preparation = _prepare(
        sample_campaign,
        surface=_iam_surface(),
        operation=CloudReadOnlyOperation.POLICY,
    )
    assert preparation.surface.surface_class.value == "iam"
    assert preparation.provider_request.operation is CloudReadOnlyOperation.POLICY

    with pytest.raises(ValidationError, match="policy read requires"):
        _route(_resource_surface(), CloudReadOnlyOperation.POLICY)


def test_surface_provider_and_route_registration_cannot_be_inferred(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    broker, lease = _broker_lease(campaign, adapter)
    reference = bind_cloud_credential_lease_reference(
        broker=broker,
        lease=lease,
        campaign=campaign,
        provider_adapter=adapter.definition,
        evaluated_at=NOW,
    )
    foreign_surface = typed_cloud_account_resource_surface(
        locator=cloud_resource_surface_locator(
            parent=cloud_account_surface_locator(
                provider_id="gcp",
                provider_partition="public",
                account_id="organization-123",
            ),
            service_id="storage",
            location_id="asia-northeast3",
            resource_type="bucket",
            resource_id="foreign-bucket",
        )
    )

    with pytest.raises(CloudReadOnlyCapabilityError, match="provider coordinate"):
        adapter.prepare_request(
            surface=foreign_surface,
            operation=CloudReadOnlyOperation.INVENTORY,
            credential_lease=reference,
        )
    with pytest.raises(CloudReadOnlyCapabilityError, match="no exact Surface"):
        adapter.prepare_request(
            surface=_iam_surface(),
            operation=CloudReadOnlyOperation.INVENTORY,
            credential_lease=reference,
        )


@pytest.mark.parametrize(
    ("campaign_kwargs", "match"),
    (
        ({"include_surface": False}, "Cloud Surface lacks an exact"),
        ({"include_provider": False}, "Cloud provider route lacks an exact"),
        ({"allow_get": False}, "reviewed GET authority"),
    ),
)
def test_preparation_requires_both_exact_scope_rules_and_get_roe(
    sample_campaign: CampaignManifest,
    campaign_kwargs: dict[str, bool],
    match: str,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(
        sample_campaign,
        surface=surface,
        adapter=adapter,
        **campaign_kwargs,
    )
    activation, release = _activation()
    broker, lease = _broker_lease(campaign, adapter)
    with pytest.raises((CloudReadOnlyCapabilityError, ValidationError), match=match):
        prepare_cloud_read_only_inventory_policy(
            activation=activation,
            release=release,
            campaign=campaign,
            surface=surface,
            operation=CloudReadOnlyOperation.INVENTORY,
            provider_adapter=adapter,
            secret_broker=broker,
            credential_lease=lease,
            evaluated_at=NOW,
            request_id="tool_cloud_scope_rejected",
            agent_id="agent:cloud-read-only",
        )


@pytest.mark.parametrize(
    ("endpoint", "target"),
    (
        ("https://127.0.0.1", "https://127.0.0.1/v1/inventory/private"),
        ("https://localhost", "https://localhost/v1/inventory/private"),
        (
            "https://host.docker.internal",
            "https://host.docker.internal/v1/inventory/private",
        ),
    ),
)
def test_preparation_requires_explicit_private_network_roe(
    sample_campaign: CampaignManifest,
    endpoint: str,
    target: str,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface, endpoint=endpoint, target=target)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    blocked_payload = campaign.model_dump(mode="json", by_alias=True)
    blocked_payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = False
    blocked_campaign = CampaignManifest.model_validate(blocked_payload)
    activation, release = _activation()
    broker, lease = _broker_lease(blocked_campaign, adapter)

    with pytest.raises(CloudReadOnlyCapabilityError, match="private-network Campaign authority"):
        prepare_cloud_read_only_inventory_policy(
            activation=activation,
            release=release,
            campaign=blocked_campaign,
            surface=surface,
            operation=CloudReadOnlyOperation.INVENTORY,
            provider_adapter=adapter,
            secret_broker=broker,
            credential_lease=lease,
            evaluated_at=NOW,
            request_id="tool_cloud_private_route_rejected",
            agent_id="agent:cloud-read-only",
        )

    allowed_payload = blocked_campaign.model_dump(mode="json", by_alias=True)
    allowed_payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = True
    allowed_campaign = CampaignManifest.model_validate(allowed_payload)
    allowed_broker, allowed_lease = _broker_lease(allowed_campaign, adapter)
    preparation = prepare_cloud_read_only_inventory_policy(
        activation=activation,
        release=release,
        campaign=allowed_campaign,
        surface=surface,
        operation=CloudReadOnlyOperation.INVENTORY,
        provider_adapter=adapter,
        secret_broker=allowed_broker,
        credential_lease=allowed_lease,
        evaluated_at=NOW,
        request_id="tool_cloud_private_route_allowed",
        agent_id="agent:cloud-read-only",
    )

    assert preparation.provider_request.target == target
    assert preparation.campaign_scope.allow_private_networks is True


@pytest.mark.parametrize("denied", ("surface", "provider"))
def test_campaign_deny_overrides_exact_cloud_allow(
    sample_campaign: CampaignManifest,
    denied: str,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    deny = (
        [cloud_surface_scope_target(surface)]
        if denied == "surface"
        else [adapter.definition.routes[0].target]
    )
    campaign = _campaign(
        sample_campaign,
        surface=surface,
        adapter=adapter,
        deny=deny,
    )
    activation, release = _activation()
    broker, lease = _broker_lease(campaign, adapter)
    with pytest.raises(CloudReadOnlyCapabilityError, match="deny rule"):
        prepare_cloud_read_only_inventory_policy(
            activation=activation,
            release=release,
            campaign=campaign,
            surface=surface,
            operation=CloudReadOnlyOperation.INVENTORY,
            provider_adapter=adapter,
            secret_broker=broker,
            credential_lease=lease,
            evaluated_at=NOW,
            request_id="tool_cloud_deny_rejected",
            agent_id="agent:cloud-read-only",
        )


@pytest.mark.parametrize(
    ("lease_factory", "match"),
    (
        (
            lambda campaign, adapter: _broker_lease(campaign, adapter, audience="other-worker"),
            "trusted SecretBroker",
        ),
        (
            lambda campaign, adapter: _broker_lease(
                campaign, adapter, scope="campaign-cloud:other"
            ),
            "trusted SecretBroker",
        ),
        (
            lambda campaign, adapter: _broker_lease(campaign, adapter, ttl_seconds=60),
            "active exact",
        ),
        (
            lambda campaign, adapter: _broker_lease(campaign, adapter, max_uses=2),
            "active exact",
        ),
    ),
)
def test_credential_lease_audience_scope_ttl_and_use_budget_fail_closed(
    sample_campaign: CampaignManifest,
    lease_factory,
    match: str,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    broker, lease = lease_factory(campaign, adapter)
    with pytest.raises(CloudReadOnlyCapabilityError, match=match):
        bind_cloud_credential_lease_reference(
            broker=broker,
            lease=lease,
            campaign=campaign,
            provider_adapter=adapter.definition,
            evaluated_at=NOW,
        )


def test_expired_revoked_and_consumed_lease_snapshots_fail_closed(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    broker, active = _broker_lease(campaign, adapter)
    variants = (
        active.model_copy(update={"status": SecretLeaseStatus.REVOKED}),
        active.model_copy(update={"remaining_uses": 0}),
    )
    for lease in variants:
        with pytest.raises(CloudReadOnlyCapabilityError, match="snapshot differs"):
            bind_cloud_credential_lease_reference(
                broker=broker,
                lease=lease,
                campaign=campaign,
                provider_adapter=adapter.definition,
                evaluated_at=NOW,
            )
    with pytest.raises(CloudReadOnlyCapabilityError, match="active exact"):
        bind_cloud_credential_lease_reference(
            broker=broker,
            lease=active,
            campaign=campaign,
            provider_adapter=adapter.definition,
            evaluated_at=NOW + timedelta(seconds=30),
        )


def test_lease_reference_requires_the_trusted_broker_snapshot(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    trusted_broker, trusted_lease = _broker_lease(campaign, adapter)
    foreign_broker, foreign_lease = _broker_lease(campaign, adapter)

    with pytest.raises(CloudReadOnlyCapabilityError, match="trusted SecretBroker"):
        bind_cloud_credential_lease_reference(
            broker=trusted_broker,
            lease=foreign_lease,
            campaign=campaign,
            provider_adapter=adapter.definition,
            evaluated_at=NOW,
        )

    forged = trusted_lease.model_copy(update={"secret_ref_fingerprint": "0" * 16})
    with pytest.raises(CloudReadOnlyCapabilityError, match="snapshot differs"):
        bind_cloud_credential_lease_reference(
            broker=trusted_broker,
            lease=forged,
            campaign=campaign,
            provider_adapter=adapter.definition,
            evaluated_at=NOW,
        )

    assert (
        foreign_broker.inspect(
            foreign_lease.lease_id,
            audience=AUDIENCE,
            scope=cloud_credential_lease_scope(campaign),
        )
        == foreign_lease
    )


def test_provider_adapter_routes_are_canonical_sorted_and_origin_bound() -> None:
    first = _route(_resource_surface(), CloudReadOnlyOperation.INVENTORY)
    second = _route(_iam_surface(), CloudReadOnlyOperation.INVENTORY)
    ordered = tuple(
        sorted(
            (first, second),
            key=lambda item: (item.surface.surface_id, item.operation.value, item.target),
        )
    )
    definition = CloudReadOnlyProviderAdapterDefinition(
        adapterId="pajin.cloud-provider.test-read-only",
        providerId="aws",
        providerPartition="aws",
        endpointOrigin=ENDPOINT,
        credentialAudience=AUDIENCE,
        routes=ordered,
    )
    assert len(definition.adapter_digest) == 64

    with pytest.raises(ValidationError, match="sorted and unique"):
        CloudReadOnlyProviderAdapterDefinition(
            adapterId="pajin.cloud-provider.test-read-only",
            providerId="aws",
            providerPartition="aws",
            endpointOrigin=ENDPOINT,
            credentialAudience=AUDIENCE,
            routes=tuple(reversed(ordered)),
        )
    duplicate_route = _route(
        _resource_surface(),
        CloudReadOnlyOperation.INVENTORY,
        target=f"{ENDPOINT}/v1/inventory/duplicate",
    )
    duplicate_pair = tuple(
        sorted(
            (first, duplicate_route),
            key=lambda item: (item.surface.surface_id, item.operation.value, item.target),
        )
    )
    with pytest.raises(ValidationError, match="sorted and unique"):
        CloudReadOnlyProviderAdapterDefinition(
            adapterId="pajin.cloud-provider.test-read-only",
            providerId="aws",
            providerPartition="aws",
            endpointOrigin=ENDPOINT,
            credentialAudience=AUDIENCE,
            routes=duplicate_pair,
        )
    with pytest.raises(ValidationError, match="endpoint origin"):
        CloudReadOnlyProviderAdapterDefinition(
            adapterId="pajin.cloud-provider.test-read-only",
            providerId="aws",
            providerPartition="aws",
            endpointOrigin=ENDPOINT,
            credentialAudience=AUDIENCE,
            routes=(
                _route(
                    _resource_surface(),
                    CloudReadOnlyOperation.INVENTORY,
                    target="https://other.example.test/v1/inventory",
                ),
            ),
        )


def test_runtime_adapter_and_worker_job_remain_unavailable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    tool = CloudReadOnlyInventoryPolicyTool()
    activation = _activation()[0]
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    oracle = activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE)

    with pytest.raises(CloudReadOnlyCapabilityError, match="does not materialize"):
        tool.prepare(preparation.prepared_action.request)
    with pytest.raises(CloudReadOnlyCapabilityError, match="does not materialize"):
        executor.prepare(preparation.prepared_action.request)
    assert (
        oracle.evaluate(
            preparation.prepared_action.request,
            ToolResult(
                request_id=preparation.prepared_action.request.request_id,
                tool_id=CLOUD_READ_ONLY_TOOL_ID,
                success=True,
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        is CapabilityOracleDecision.INCONCLUSIVE
    )


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_cloud_read_only_inventory_policy_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        CloudReadOnlyInventoryPolicyBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        CloudReadOnlyInventoryPolicyBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _PREPARATION_FALSE_MARKERS)
def test_preparation_rejects_authority_escalation(
    alias: str, sample_campaign: CampaignManifest
) -> None:
    payload = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["preparationDigest"] = ""
    with pytest.raises(ValidationError):
        CloudReadOnlyInventoryPolicyPreparation.model_validate(payload)


def test_preparation_rejects_surface_route_lease_request_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("providerRequest", "routeDigest", "0" * 64),
        ("credentialLease", "referenceDigest", "0" * 64),
        ("campaignScope", "campaignDigest", "0" * 64),
        ("campaignScope", "allowPrivateNetworks", True),
        ("preparedAction", "requestDigest", "0" * 64),
        (None, "matchedProviderAllowRule", "https://other.example.test/v1/read"),
        (None, "preparationDigest", "0" * 64),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            CloudReadOnlyInventoryPolicyPreparation.model_validate(payload)


def test_lease_reference_rejects_bearer_and_secret_metadata_injection(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    payload = preparation.credential_lease.model_dump(mode="json", by_alias=True)
    for field, value in (
        ("leaseId", "lease_injected"),
        ("secretRef", SECRET_REF),
        ("credentialMaterial", SECRET_VALUE),
    ):
        changed = {**payload, field: value}
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CloudCredentialLeaseReference.model_validate(changed)


def test_stale_or_substituted_release_fails_before_preparation(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _resource_surface()
    adapter = _adapter(surface)
    campaign = _campaign(sample_campaign, surface=surface, adapter=adapter)
    activation, release = _activation()
    broker, lease = _broker_lease(campaign, adapter)
    with pytest.raises(CloudReadOnlyCapabilityError):
        prepare_cloud_read_only_inventory_policy(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            campaign=campaign,
            surface=surface,
            operation=CloudReadOnlyOperation.INVENTORY,
            provider_adapter=adapter,
            secret_broker=broker,
            credential_lease=lease,
            evaluated_at=NOW,
            request_id="tool_cloud_stale_release",
            agent_id="agent:cloud-read-only",
        )


def test_tool_request_rejects_target_or_method_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    request = _prepare(sample_campaign).prepared_action.request
    tool = CloudReadOnlyInventoryPolicyTool()
    for changed in (
        request.model_copy(update={"target": f"{ENDPOINT}/v1/other"}),
        request.model_copy(update={"method": "POST"}),
    ):
        with pytest.raises(CloudReadOnlyCapabilityError, match="differs from bounded GET"):
            tool.prepare(changed)


def test_credential_binding_constant_matches_adapter_contract() -> None:
    assert CLOUD_CREDENTIAL_BINDING == "cloud-provider-credential"
