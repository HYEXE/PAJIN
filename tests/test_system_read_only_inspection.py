from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities.authorities import CapabilityAuthorityRole, CapabilityOracleDecision
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
from pajin.capabilities.system_inspection import (
    SYSTEM_READ_ONLY_CAPABILITY_ID,
    SYSTEM_READ_ONLY_TOOL_ID,
    BoundedSystemHostAgentAdapter,
    SystemHostAgentDeploymentBinding,
    SystemHostAgentDeploymentRef,
    SystemHostAgentInspectionRequest,
    SystemReadOnlyCapabilityActivation,
    SystemReadOnlyCapabilityError,
    SystemReadOnlyInspectionBinding,
    SystemReadOnlyInspectionPreparation,
    SystemReadOnlyInspectionTool,
    SystemReadOnlyOperation,
    activate_system_read_only_capability,
    bind_system_host_agent_deployment,
    prepare_system_read_only_inspection,
    registered_system_read_only_capability_definition,
    registered_system_read_only_capability_domain_classification,
    registered_system_read_only_inspection_binding,
    resolve_system_read_only_capability_domain_classification,
    resolve_system_read_only_inspection_binding,
    system_read_only_capability_bundle,
    system_surface_scope_target,
    worker_mtls_trust_policy_digest,
)
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSTrustPolicy,
)
from pajin.discovery import (
    SystemArchitecture,
    SystemFilesystemEntryKind,
    SystemHostResourceSurface,
    SystemOperatingSystem,
    SystemServiceManager,
    SystemSurfaceClass,
    system_configuration_surface_locator,
    system_filesystem_surface_locator,
    system_host_surface_locator,
    system_process_surface_locator,
    system_service_surface_locator,
    typed_system_host_resource_surface,
)
from pajin.domain.models import CampaignManifest, ToolResult, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.tools.base import ToolRegistry

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
HOST_ID = f"host-{sha256(b'system-host-a').hexdigest()}"
FOREIGN_HOST_ID = f"host-{sha256(b'system-host-b').hexdigest()}"
CERTIFICATE_DIGEST = sha256(b"system-host-agent-certificate").hexdigest()
EXECUTABLE_DIGEST = sha256(b"system-host-agent-executable").hexdigest()

_BINDING_FALSE_MARKERS = (
    "agentSessionOpened",
    "hostConnectionOpened",
    "hostReadAuthorized",
    "processInspectionAuthorized",
    "filesystemReadAuthorized",
    "serviceInspectionAuthorized",
    "configurationReadAuthorized",
    "serviceControlAuthorized",
    "hostMutationAuthorized",
    "credentialUseAuthorized",
    "rootAuthorityAsserted",
    "privilegeEscalationAuthorized",
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
_DEPLOYMENT_FALSE_MARKERS = (
    "bearerAuthenticated",
    "liveDirectMTLSAuthenticated",
    "nonRootRuntimeVerified",
    "agentSessionOpened",
    "hostConnectionOpened",
    "hostAccessAuthorized",
    "credentialUseAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "rootAuthorityAsserted",
    "privilegeEscalationAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_PREPARATION_FALSE_MARKERS = (
    "liveHostAgentRuntimeAvailable",
    "bearerAuthenticated",
    "liveDirectMTLSAuthenticated",
    "nonRootRuntimeVerified",
    "agentSessionOpened",
    "hostConnectionOpened",
    "hostReadAuthorized",
    "processInspectionAuthorized",
    "filesystemReadAuthorized",
    "serviceInspectionAuthorized",
    "configurationReadAuthorized",
    "serviceControlAuthorized",
    "hostMutationAuthorized",
    "credentialUseAuthorized",
    "rootAuthorityAsserted",
    "privilegeEscalationAuthorized",
    "budgetReserved",
    "workerJobMaterialized",
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
    return sha256(f"system-read-only:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"system-read-only.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


def _activation() -> tuple[SystemReadOnlyCapabilityActivation, CapabilityReleaseRef]:
    tools = ToolRegistry()
    tools.register(SystemReadOnlyInspectionTool())
    bundle = system_read_only_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="system-read-only.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="system-read-only.reviewer",
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
        checklistDigest=sha256(b"system-read-only-review").hexdigest(),
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
        activate_system_read_only_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


def _host_locator(host_id: str = HOST_ID):
    return system_host_surface_locator(
        host_id=host_id,
        operating_system=SystemOperatingSystem.LINUX,
        architecture=SystemArchitecture.X86_64,
    )


def _surface(
    surface_class: SystemSurfaceClass = SystemSurfaceClass.HOST,
) -> SystemHostResourceSurface:
    host = _host_locator()
    if surface_class is SystemSurfaceClass.HOST:
        locator = host
    elif surface_class is SystemSurfaceClass.PROCESS:
        locator = system_process_surface_locator(
            host=host,
            process_instance_digest=sha256(b"process-instance").hexdigest(),
            executable_digest=sha256(b"process-executable").hexdigest(),
        )
    elif surface_class is SystemSurfaceClass.FILESYSTEM:
        locator = system_filesystem_surface_locator(
            host=host,
            mount_id="system-root",
            relative_path="etc/os-release",
            entry_kind=SystemFilesystemEntryKind.FILE,
            content_digest=sha256(b"filesystem-entry").hexdigest(),
        )
    elif surface_class is SystemSurfaceClass.SERVICE:
        locator = system_service_surface_locator(
            host=host,
            service_manager=SystemServiceManager.SYSTEMD,
            service_id="pajin-agent.service",
            definition_digest=sha256(b"service-definition").hexdigest(),
        )
    else:
        service = system_service_surface_locator(
            host=host,
            service_manager=SystemServiceManager.SYSTEMD,
            service_id="pajin-agent.service",
            definition_digest=sha256(b"service-definition").hexdigest(),
        )
        locator = system_configuration_surface_locator(
            parent=service,
            configuration_namespace="service-unit",
            configuration_id="hardening/restart-policy",
            configuration_digest=sha256(b"configuration-record").hexdigest(),
        )
    return typed_system_host_resource_surface(locator=locator)


def _certificate() -> WorkerCertificateBinding:
    return WorkerCertificateBinding(
        principal_subject="worker:system-host-agent",
        certificate_spki_sha256=CERTIFICATE_DIGEST,
    )


def _policy(*bindings: WorkerCertificateBinding) -> WorkerMTLSTrustPolicy:
    return WorkerMTLSTrustPolicy(
        policy_id=f"worker-mtls-policy_{sha256(b'system-policy').hexdigest()[:32]}",
        bindings=bindings or (_certificate(),),
    )


def _deployment(
    *,
    host_id: str = HOST_ID,
    allowed_operations: tuple[SystemReadOnlyOperation, ...] | None = None,
) -> SystemHostAgentDeploymentBinding:
    return bind_system_host_agent_deployment(
        deployment_id="deployment:system-host-a",
        authorized_host_id=host_id,
        trust_policy=_policy(),
        certificate_binding=_certificate(),
        agent_executable_sha256=EXECUTABLE_DIGEST,
        run_as_identity="svc:pajin-host-agent",
        allowed_operations=allowed_operations
        or tuple(sorted(SystemReadOnlyOperation, key=lambda item: item.value)),
        max_artifact_bytes=131_072,
        max_runtime_seconds=30,
    )


def _operation(surface: SystemHostResourceSurface) -> SystemReadOnlyOperation:
    return {
        SystemSurfaceClass.HOST: SystemReadOnlyOperation.HOST_METADATA,
        SystemSurfaceClass.PROCESS: SystemReadOnlyOperation.PROCESS_METADATA,
        SystemSurfaceClass.FILESYSTEM: SystemReadOnlyOperation.FILESYSTEM_METADATA,
        SystemSurfaceClass.SERVICE: SystemReadOnlyOperation.SERVICE_STATUS,
        SystemSurfaceClass.CONFIGURATION: SystemReadOnlyOperation.CONFIGURATION_METADATA,
    }[surface.surface_class]


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    surface: SystemHostResourceSurface,
    include_surface: bool = True,
    allow_get: bool = True,
    allow_private: bool = True,
    deny: list[str] | None = None,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    allow: list[str] = []
    if include_surface:
        allow.append(system_surface_scope_target(surface))
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
    payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = allow_private
    return CampaignManifest.model_validate(payload)


def _prepare(
    sample_campaign: CampaignManifest,
    *,
    surface: SystemHostResourceSurface | None = None,
) -> SystemReadOnlyInspectionPreparation:
    selected_surface = surface or _surface()
    deployment = _deployment()
    campaign = _campaign(
        sample_campaign,
        surface=selected_surface,
    )
    activation, release = _activation()
    return prepare_system_read_only_inspection(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=selected_surface,
        operation=_operation(selected_surface),
        host_agent=BoundedSystemHostAgentAdapter(deployment),
        request_id="tool_system_read_only_prepare",
        agent_id="agent:system-read-only",
    )


def test_capability_binding_pins_system_cap_002_and_worker_boundary() -> None:
    definition = registered_system_read_only_capability_definition()
    binding = registered_system_read_only_inspection_binding()
    tools = ToolRegistry()
    tools.register(SystemReadOnlyInspectionTool())
    bundle = system_read_only_capability_bundle(tools)
    worker = resolve_registered_domain_worker_boundary_profile(binding.worker_profile)

    assert definition.capability_id == SYSTEM_READ_ONLY_CAPABILITY_ID
    assert definition.supported_surface_types == (
        "system-configuration",
        "system-filesystem",
        "system-host",
        "system-process",
        "system-service",
    )
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is False
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert binding.capability == bundle.capability()
    assert worker.network_boundary is WorkerNetworkBoundary.DEPLOYMENT_SCOPED
    assert worker.filesystem_boundary is WorkerFilesystemBoundary.BOUNDED_HOST_READ
    assert worker.credential_boundary is WorkerCredentialBoundary.DEPLOYMENT_AUTHENTICATION
    assert worker.runtime_boundary is WorkerRuntimeBoundary.AUTHENTICATED_NON_ROOT_AGENT
    assert worker.required_identity_dimensions == ("authorized-host", "host-agent")
    assert worker.required_budget_dimensions == ("artifact-bytes", "runtime")
    payload = binding.model_dump(mode="json", by_alias=True)
    assert all(payload[alias] is False for alias in _BINDING_FALSE_MARKERS)
    classification = registered_system_read_only_capability_domain_classification()
    assert classification.domain_classification.domain is SecurityDomain.SYSTEM
    assert (
        resolve_system_read_only_capability_domain_classification(classification.reference())
        == classification
    )
    assert resolve_system_read_only_inspection_binding(binding.reference()) == binding


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("toolId", "attacker.substituted-system-tool"),
        ("toolVersion", "9.9.9"),
        ("toolDigest", "0" * 64),
        ("riskTier", 0),
    ),
)
def test_activation_rejects_recomputed_action_metadata_substitution(
    field: str,
    replacement: str | int,
) -> None:
    activation, _ = _activation()
    original_set = activation.activation_set
    original_payload = original_set.model_dump(mode="json", by_alias=True)
    assert type(original_set).model_validate(original_payload) == original_set
    expected_action = original_set.binding.action_capability
    assert activation.action_registry().resolve(expected_action.reference()) == expected_action

    payload = deepcopy(original_payload)
    payload["binding"]["actionCapability"][field] = replacement
    payload["binding"]["actionCapability"]["capabilityDigest"] = ""
    tampered_action = type(expected_action).model_validate(payload["binding"]["actionCapability"])
    assert tampered_action.capability_digest != expected_action.capability_digest
    payload["binding"]["actionCapability"] = tampered_action.model_dump(
        mode="json",
        by_alias=True,
    )
    payload["activationSetId"] = ""
    payload["activationSetDigest"] = ""
    with pytest.raises(ValidationError, match="activation references another Capability"):
        type(original_set).model_validate(payload)


def test_activation_rejects_authority_set_identity_substitution() -> None:
    original_set = _activation()[0].activation_set
    payload = original_set.model_dump(mode="json", by_alias=True)
    payload["binding"]["capability"]["authoritySetId"] = f"capability-authority-set_{'0' * 64}"
    payload["binding"]["capability"]["authoritySetDigest"] = "0" * 64
    payload["activationSetId"] = ""
    payload["activationSetDigest"] = ""

    with pytest.raises(ValidationError, match="activation references another Capability"):
        type(original_set).model_validate(payload)


def test_host_agent_deployment_pins_mtls_non_root_and_budgets_without_authentication() -> None:
    deployment = _deployment()
    payload = deployment.model_dump(mode="json", by_alias=True)

    assert deployment.worker_mtls_policy_digest == worker_mtls_trust_policy_digest(_policy())
    assert deployment.certificate_binding == _certificate()
    assert deployment.run_as_identity == "svc:pajin-host-agent"
    assert deployment.max_artifact_bytes == 131_072
    assert deployment.max_runtime_seconds == 30
    assert all(payload[alias] is False for alias in _DEPLOYMENT_FALSE_MARKERS)
    assert deployment.deployment_binding_id == (
        f"system-host-agent-deployment_{deployment.deployment_binding_digest}"
    )
    assert SystemHostAgentDeploymentBinding.model_validate(payload) == deployment
    reference_payload = deployment.reference().model_dump(mode="json", by_alias=True)
    reference_payload["deploymentBindingId"] = f"system-host-agent-deployment_{'0' * 64}"
    with pytest.raises(ValidationError, match="reference identity differs"):
        SystemHostAgentDeploymentRef.model_validate(reference_payload)


@pytest.mark.parametrize("surface_class", tuple(SystemSurfaceClass))
def test_adapter_maps_each_exact_surface_to_only_its_metadata_operation(
    surface_class: SystemSurfaceClass,
) -> None:
    surface = _surface(surface_class)
    request = BoundedSystemHostAgentAdapter(_deployment()).prepare_request(
        surface=surface,
        operation=_operation(surface),
    )
    payload = request.model_dump(mode="json", by_alias=True)

    assert request.surface == surface
    assert request.target == system_surface_scope_target(surface)
    assert request.method == "GET"
    assert request.budget.request_count == 1
    assert request.budget.max_artifact_bytes == 131_072
    assert request.budget.runtime_seconds == 30
    assert request.budget.filesystem_content_reads == 0
    assert request.budget.configuration_value_reads == 0
    assert request.budget.process_signals == 0
    assert request.budget.service_control_operations == 0
    assert request.budget.host_write_operations == 0
    assert SystemHostAgentInspectionRequest.model_validate(payload) == request


def test_signed_preparation_binds_scope_worker_budget_and_capability_without_dispatch(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    request = preparation.prepared_action.request
    payload = preparation.model_dump(mode="json", by_alias=True)

    assert preparation.state == "prepared-not-authorized"
    assert preparation.matched_surface_allow_rule == system_surface_scope_target(
        preparation.surface
    )
    assert request.method == "GET"
    assert request.target == system_surface_scope_target(preparation.surface)
    assert request.arguments == preparation.inspection_request.model_dump(
        mode="json", by_alias=True
    )
    assert all(payload[alias] is False for alias in _PREPARATION_FALSE_MARKERS)
    assert preparation.preparation_id == (
        f"system-read-only-preparation_{preparation.preparation_digest}"
    )
    assert SystemReadOnlyInspectionPreparation.model_validate(payload) == preparation


def test_surface_host_and_operation_cannot_be_inferred_or_substituted() -> None:
    surface = _surface(SystemSurfaceClass.SERVICE)
    adapter = BoundedSystemHostAgentAdapter(_deployment())
    with pytest.raises(SystemReadOnlyCapabilityError, match="Surface class"):
        adapter.prepare_request(
            surface=surface,
            operation=SystemReadOnlyOperation.HOST_METADATA,
        )

    foreign = typed_system_host_resource_surface(locator=_host_locator(FOREIGN_HOST_ID))
    with pytest.raises(SystemReadOnlyCapabilityError, match="authorized host"):
        adapter.prepare_request(
            surface=foreign,
            operation=SystemReadOnlyOperation.HOST_METADATA,
        )
    request_payload = adapter.prepare_request(
        surface=_surface(),
        operation=SystemReadOnlyOperation.HOST_METADATA,
    ).model_dump(mode="json", by_alias=True)
    request_payload["surface"] = foreign.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError, match="authorized host"):
        SystemHostAgentInspectionRequest.model_validate(request_payload)

    host_only = _deployment(
        allowed_operations=(SystemReadOnlyOperation.HOST_METADATA,),
    )
    with pytest.raises(SystemReadOnlyCapabilityError, match="outside the host-agent"):
        BoundedSystemHostAgentAdapter(host_only).prepare_request(
            surface=surface,
            operation=SystemReadOnlyOperation.SERVICE_STATUS,
        )


@pytest.mark.parametrize(
    ("campaign_kwargs", "match"),
    (
        ({"include_surface": False}, "System Surface lacks an exact"),
        ({"allow_get": False}, "reviewed GET authority"),
    ),
)
def test_preparation_requires_exact_surface_scope_and_get_authority(
    sample_campaign: CampaignManifest,
    campaign_kwargs: dict[str, bool],
    match: str,
) -> None:
    surface = _surface()
    deployment = _deployment()
    campaign = _campaign(
        sample_campaign,
        surface=surface,
        **campaign_kwargs,
    )
    activation, release = _activation()
    with pytest.raises((SystemReadOnlyCapabilityError, ValidationError), match=match):
        prepare_system_read_only_inspection(
            activation=activation,
            release=release,
            campaign=campaign,
            surface=surface,
            operation=SystemReadOnlyOperation.HOST_METADATA,
            host_agent=BoundedSystemHostAgentAdapter(deployment),
            request_id="tool_system_scope_rejected",
            agent_id="agent:system-read-only",
        )


def test_campaign_deny_overrides_exact_system_surface_allow(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    deployment = _deployment()
    deny = [system_surface_scope_target(surface)]
    campaign = _campaign(
        sample_campaign,
        surface=surface,
        deny=deny,
    )
    activation, release = _activation()
    with pytest.raises(SystemReadOnlyCapabilityError, match="deny rule"):
        prepare_system_read_only_inspection(
            activation=activation,
            release=release,
            campaign=campaign,
            surface=surface,
            operation=SystemReadOnlyOperation.HOST_METADATA,
            host_agent=BoundedSystemHostAgentAdapter(deployment),
            request_id="tool_system_deny_rejected",
            agent_id="agent:system-read-only",
        )


def test_host_local_preparation_does_not_require_private_network_scope(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    deployment = _deployment()
    campaign = _campaign(
        sample_campaign,
        surface=surface,
        allow_private=False,
    )
    activation, release = _activation()

    preparation = prepare_system_read_only_inspection(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=surface,
        operation=SystemReadOnlyOperation.HOST_METADATA,
        host_agent=BoundedSystemHostAgentAdapter(deployment),
        request_id="tool_system_host_local_prepare",
        agent_id="agent:system-read-only",
    )

    assert preparation.campaign_scope.allow_private_networks is False
    assert preparation.inspection_request.target == system_surface_scope_target(surface)
    assert preparation.inspection_request.network_access_authorized is False


@pytest.mark.parametrize(
    "identity",
    (
        "root",
        "administrator",
        "SYSTEM",
        "uid:0",
        "uid:000",
        "00",
        "local-system",
        "corp:administrator",
        "root@host",
        "S-1-5-18",
        "S-1-5-21-1000-1000-1000-500",
    ),
)
def test_deployment_rejects_root_and_privileged_aliases(identity: str) -> None:
    with pytest.raises(SystemReadOnlyCapabilityError, match="non-root"):
        bind_system_host_agent_deployment(
            deployment_id="deployment:system-host-a",
            authorized_host_id=HOST_ID,
            trust_policy=_policy(),
            certificate_binding=_certificate(),
            agent_executable_sha256=EXECUTABLE_DIGEST,
            run_as_identity=identity,
        )


def test_deployment_rejects_untrusted_certificate_unsorted_operations_and_route_injection() -> None:
    foreign = WorkerCertificateBinding(
        principal_subject="worker:foreign-agent",
        certificate_spki_sha256=sha256(b"foreign-certificate").hexdigest(),
    )
    with pytest.raises(SystemReadOnlyCapabilityError, match="outside the exact mTLS"):
        bind_system_host_agent_deployment(
            deployment_id="deployment:system-host-a",
            authorized_host_id=HOST_ID,
            trust_policy=_policy(),
            certificate_binding=foreign,
            agent_executable_sha256=EXECUTABLE_DIGEST,
            run_as_identity="svc:pajin-host-agent",
        )
    payload = _deployment().model_dump(mode="json", by_alias=True)
    payload["certificateBinding"] = foreign.model_dump(mode="json")
    payload["deploymentBindingDigest"] = ""
    with pytest.raises(ValidationError, match="code authority"):
        SystemHostAgentDeploymentBinding.model_validate(payload)
    with pytest.raises(SystemReadOnlyCapabilityError, match="sorted and unique"):
        _deployment(
            allowed_operations=(
                SystemReadOnlyOperation.SERVICE_STATUS,
                SystemReadOnlyOperation.HOST_METADATA,
            )
        )
    payload = _deployment().model_dump(mode="json", by_alias=True)
    payload["agentEndpoint"] = "https://127.0.0.1:9443/v1/system-inspection"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SystemHostAgentDeploymentBinding.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("maxArtifactBytes", 1_023),
        ("maxArtifactBytes", 1_048_577),
        ("maxArtifactBytes", True),
        ("maxRuntimeSeconds", 0),
        ("maxRuntimeSeconds", 61),
        ("maxRuntimeSeconds", True),
    ),
)
def test_deployment_budget_bounds_and_integer_types_fail_closed(
    field: str,
    value: int | bool,
) -> None:
    payload = _deployment().model_dump(mode="json", by_alias=True)
    payload[field] = value
    payload["deploymentBindingDigest"] = ""
    with pytest.raises(ValidationError):
        SystemHostAgentDeploymentBinding.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("requestCount", 2),
        ("filesystemContentReads", 1),
        ("configurationValueReads", 1),
        ("processSignals", 1),
        ("serviceControlOperations", 1),
        ("hostWriteOperations", 1),
    ),
)
def test_request_cannot_expand_read_or_mutation_budget(field: str, value: int) -> None:
    request = BoundedSystemHostAgentAdapter(_deployment()).prepare_request(
        surface=_surface(),
        operation=SystemReadOnlyOperation.HOST_METADATA,
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] = value
    with pytest.raises(ValidationError):
        SystemHostAgentInspectionRequest.model_validate(payload)


def test_runtime_adapter_and_worker_job_remain_unavailable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    tool = SystemReadOnlyInspectionTool()
    activation = _activation()[0]
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    oracle = activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE)

    with pytest.raises(SystemReadOnlyCapabilityError, match="does not materialize"):
        tool.prepare(preparation.prepared_action.request)
    with pytest.raises(SystemReadOnlyCapabilityError, match="does not materialize"):
        executor.prepare(preparation.prepared_action.request)
    assert (
        oracle.evaluate(
            preparation.prepared_action.request,
            ToolResult(
                request_id=preparation.prepared_action.request.request_id,
                tool_id=SYSTEM_READ_ONLY_TOOL_ID,
                success=True,
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        is CapabilityOracleDecision.INCONCLUSIVE
    )


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_system_read_only_inspection_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        SystemReadOnlyInspectionBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        SystemReadOnlyInspectionBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _DEPLOYMENT_FALSE_MARKERS)
def test_deployment_rejects_live_authority_escalation(alias: str) -> None:
    payload = _deployment().model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["deploymentBindingDigest"] = ""
    with pytest.raises(ValidationError):
        SystemHostAgentDeploymentBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _PREPARATION_FALSE_MARKERS)
def test_preparation_rejects_authority_escalation(
    alias: str,
    sample_campaign: CampaignManifest,
) -> None:
    payload = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["preparationDigest"] = ""
    with pytest.raises(ValidationError):
        SystemReadOnlyInspectionPreparation.model_validate(payload)


def test_preparation_rejects_surface_agent_request_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("hostAgentDeployment", "authorizedHostId", FOREIGN_HOST_ID),
        ("hostAgentDeployment", "workerMTLSPolicyDigest", "0" * 64),
        (
            "inspectionRequest",
            "target",
            system_surface_scope_target(_surface(SystemSurfaceClass.PROCESS)),
        ),
        ("campaignScope", "campaignDigest", "0" * 64),
        ("preparedAction", "requestDigest", "0" * 64),
        (None, "preparationDigest", "0" * 64),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            SystemReadOnlyInspectionPreparation.model_validate(payload)


def test_stale_release_and_tool_request_substitution_fail_closed(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    deployment = _deployment()
    campaign = _campaign(
        sample_campaign,
        surface=surface,
    )
    activation, release = _activation()
    with pytest.raises(SystemReadOnlyCapabilityError):
        prepare_system_read_only_inspection(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            campaign=campaign,
            surface=surface,
            operation=SystemReadOnlyOperation.HOST_METADATA,
            host_agent=BoundedSystemHostAgentAdapter(deployment),
            request_id="tool_system_stale_release",
            agent_id="agent:system-read-only",
        )

    request = _prepare(sample_campaign).prepared_action.request
    tool = SystemReadOnlyInspectionTool()
    for changed in (
        request.model_copy(update={"target": "https://other.example.test/v1/inspect"}),
        request.model_copy(update={"method": "POST"}),
    ):
        with pytest.raises(SystemReadOnlyCapabilityError, match="bounded GET"):
            tool.prepare(changed)


def test_deployment_and_request_reject_secret_or_live_admission_injection() -> None:
    deployment = _deployment()
    deployment_payload = deployment.model_dump(mode="json", by_alias=True)
    for field, value in (
        ("bearerToken", "secret-token"),
        ("privateKey", "secret-key"),
        ("workerMTLSAdmission", {"directMTLSAuthenticated": True}),
    ):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SystemHostAgentDeploymentBinding.model_validate({**deployment_payload, field: value})

    request = BoundedSystemHostAgentAdapter(deployment).prepare_request(
        surface=_surface(),
        operation=SystemReadOnlyOperation.HOST_METADATA,
    )
    request_payload = request.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SystemHostAgentInspectionRequest.model_validate(
            {**request_payload, "credentialMaterial": "secret"}
        )
