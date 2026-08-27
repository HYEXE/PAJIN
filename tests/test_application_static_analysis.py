from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities.application_static_analysis import (
    APPLICATION_ARTIFACT_MOUNT_TARGET,
    APPLICATION_STATIC_ANALYSIS_CAPABILITY_ID,
    APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA,
    APPLICATION_STATIC_ANALYSIS_TOOL_ID,
    ApplicationArtifactCustodyBinding,
    ApplicationArtifactCustodyRef,
    ApplicationStaticAnalysisBinding,
    ApplicationStaticAnalysisCapabilityActivation,
    ApplicationStaticAnalysisCapabilityError,
    ApplicationStaticAnalysisOperation,
    ApplicationStaticAnalysisPreparation,
    ApplicationStaticAnalysisRequest,
    ApplicationStaticAnalysisSandboxBinding,
    ApplicationStaticAnalysisSandboxRef,
    ApplicationStaticAnalysisTool,
    ApplicationStaticParser,
    BoundedApplicationStaticAnalyzerAdapter,
    activate_application_static_analysis_capability,
    application_static_analysis_capability_bundle,
    application_surface_scope_target,
    bind_application_artifact_custody,
    bind_application_static_analysis_sandbox,
    prepare_application_static_analysis,
    registered_application_static_analysis_binding,
    registered_application_static_analysis_capability_definition,
    registered_application_static_analysis_capability_domain_classification,
    resolve_application_static_analysis_binding,
    resolve_application_static_analysis_capability_domain_classification,
)
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
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.discovery import (
    ApplicationArtifactRuntimeSurface,
    ApplicationSurfaceClass,
    application_binary_surface_locator,
    application_configuration_surface_locator,
    application_library_surface_locator,
    application_runtime_surface_locator,
    typed_application_artifact_runtime_surface,
)
from pajin.domain.models import CampaignManifest, ToolResult, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.tools.base import ToolRegistry

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
AUTHORIZATION_DIGEST = sha256(b"application-custody-authorization").hexdigest()
PARSER_DIGEST = sha256(b"application-static-parser").hexdigest()
SANDBOX_IMAGE_DIGEST = sha256(b"application-static-sandbox-image").hexdigest()

_BINDING_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "artifactResolved",
    "artifactReadAuthorized",
    "staticAnalysisAuthorized",
    "sandboxSelected",
    "workerSelectionAuthorized",
    "artifactMountMaterialized",
    "networkAccessAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
    "artifactMutationAuthorized",
    "observationProductionAuthorized",
    "evidenceSealingAuthorized",
    "graphAdmissionAuthorized",
    "findingAuthority",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_CUSTODY_FALSE_MARKERS = (
    "rawArtifactContentEmbedded",
    "mutablePathEmbedded",
    "secretMaterialEmbedded",
    "authorizationVerifiedByPreparation",
    "custodyRuntimeVerified",
    "artifactResolved",
    "artifactBytesVerified",
    "artifactReadAuthorized",
    "mountMaterialized",
    "executionAuthorized",
)
_SANDBOX_FALSE_MARKERS = (
    "hostFilesystemAccessAllowed",
    "credentialInjectionAllowed",
    "environmentInheritanceAllowed",
    "symlinkTraversalAllowed",
    "runtimeAttested",
    "sandboxSelected",
    "artifactMountMaterialized",
    "artifactReadAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "dynamicTargetExecutionAuthorized",
    "debuggerAttachAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_PREPARATION_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "authorizationVerifiedByPreparation",
    "artifactResolved",
    "artifactBytesVerified",
    "artifactReadPerformed",
    "sandboxRuntimeAvailable",
    "sandboxRuntimeAttested",
    "sandboxSelected",
    "artifactMountMaterialized",
    "budgetReserved",
    "workerJobMaterialized",
    "networkRequestPerformed",
    "dynamicTargetExecutionPerformed",
    "debuggerAttached",
    "artifactMutated",
    "observationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "findingProduced",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "executionAuthorized",
)


def _seed(label: str) -> bytes:
    return sha256(f"application-static-analysis:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"application-static-analysis.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


def _activation() -> tuple[
    ApplicationStaticAnalysisCapabilityActivation,
    CapabilityReleaseRef,
]:
    tools = ToolRegistry()
    tools.register(ApplicationStaticAnalysisTool())
    bundle = application_static_analysis_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="application-static-analysis.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="application-static-analysis.reviewer",
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
        checklistDigest=sha256(b"application-static-analysis-review").hexdigest(),
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
        activate_application_static_analysis_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


def _surface(
    surface_class: ApplicationSurfaceClass = ApplicationSurfaceClass.BINARY,
) -> ApplicationArtifactRuntimeSurface:
    binary = application_binary_surface_locator(artifact_sha256="1" * 64)
    if surface_class is ApplicationSurfaceClass.BINARY:
        locator = binary
    elif surface_class is ApplicationSurfaceClass.CONFIGURATION:
        locator = application_configuration_surface_locator(
            parent=binary,
            configuration_namespace="pajin.app",
            configuration_id="production",
            artifact_sha256="2" * 64,
        )
    elif surface_class is ApplicationSurfaceClass.RUNTIME:
        locator = application_runtime_surface_locator(
            parent=binary,
            runtime_family="python",
            runtime_version="3.12.7",
            artifact_sha256="3" * 64,
        )
    else:
        runtime = application_runtime_surface_locator(
            parent=binary,
            runtime_family="python",
            runtime_version="3.12.7",
            artifact_sha256="3" * 64,
        )
        locator = application_library_surface_locator(
            parent=runtime,
            library_namespace="pypi",
            library_id="pydantic",
            library_version="2.11.7",
            artifact_sha256="4" * 64,
        )
    return typed_application_artifact_runtime_surface(locator=locator)


def _operation(surface: ApplicationArtifactRuntimeSurface) -> ApplicationStaticAnalysisOperation:
    return {
        ApplicationSurfaceClass.BINARY: ApplicationStaticAnalysisOperation.BINARY_METADATA,
        ApplicationSurfaceClass.CONFIGURATION: (
            ApplicationStaticAnalysisOperation.CONFIGURATION_STRUCTURE
        ),
        ApplicationSurfaceClass.RUNTIME: ApplicationStaticAnalysisOperation.RUNTIME_METADATA,
        ApplicationSurfaceClass.LIBRARY: ApplicationStaticAnalysisOperation.LIBRARY_METADATA,
    }[surface.surface_class]


def _custody(
    surface: ApplicationArtifactRuntimeSurface,
    *,
    artifact_bytes: int = 4_096,
) -> ApplicationArtifactCustodyBinding:
    return bind_application_artifact_custody(
        surface=surface,
        custody_authority_id="deployment:application-artifacts",
        custody_object_id=f"object-{surface.surface_digest}",
        authorization_id="authorization-app-001b",
        authorization_digest=AUTHORIZATION_DIGEST,
        artifact_bytes=artifact_bytes,
    )


def _sandbox(
    operation: ApplicationStaticAnalysisOperation,
    *,
    max_artifact_bytes: int = 65_536,
) -> ApplicationStaticAnalysisSandboxBinding:
    return bind_application_static_analysis_sandbox(
        deployment_id="deployment:application-static-analysis",
        operation=operation,
        parser_executable_sha256=PARSER_DIGEST,
        sandbox_image_sha256=SANDBOX_IMAGE_DIGEST,
        run_as_identity="svc:pajin-analyzer",
        max_artifact_bytes=max_artifact_bytes,
        max_output_bytes=131_072,
        max_runtime_seconds=30,
        max_memory_mib=256,
        max_process_count=4,
    )


def _adapter(
    surface: ApplicationArtifactRuntimeSurface,
    *,
    artifact_bytes: int = 4_096,
    max_artifact_bytes: int = 65_536,
) -> BoundedApplicationStaticAnalyzerAdapter:
    operation = _operation(surface)
    return BoundedApplicationStaticAnalyzerAdapter(
        _custody(surface, artifact_bytes=artifact_bytes),
        _sandbox(operation, max_artifact_bytes=max_artifact_bytes),
    )


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    surface: ApplicationArtifactRuntimeSurface,
    include_surface: bool = True,
    allow_get: bool = True,
    allow_private: bool = False,
    deny: list[str] | None = None,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    allow: list[str] = []
    if include_surface:
        allow.append(application_surface_scope_target(surface))
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
    surface: ApplicationArtifactRuntimeSurface | None = None,
) -> ApplicationStaticAnalysisPreparation:
    selected_surface = surface or _surface()
    activation, release = _activation()
    return prepare_application_static_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=selected_surface),
        surface=selected_surface,
        operation=_operation(selected_surface),
        analyzer=_adapter(selected_surface),
        request_id="tool_application_static_analysis_prepare",
        agent_id="agent:application-static-analysis",
    )


def test_capability_binding_pins_application_cap_002_and_offline_worker_boundary() -> None:
    definition = registered_application_static_analysis_capability_definition()
    binding = registered_application_static_analysis_binding()
    tools = ToolRegistry()
    tools.register(ApplicationStaticAnalysisTool())
    bundle = application_static_analysis_capability_bundle(tools)
    worker = resolve_registered_domain_worker_boundary_profile(binding.worker_profile)

    assert definition.capability_id == APPLICATION_STATIC_ANALYSIS_CAPABILITY_ID
    assert definition.supported_surface_types == (
        "application-binary",
        "application-configuration",
        "application-library",
        "application-runtime",
    )
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is False
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert binding.capability == bundle.capability()
    assert worker.network_boundary is WorkerNetworkBoundary.DISABLED_BY_DEFAULT
    assert worker.filesystem_boundary is WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
    assert worker.credential_boundary is WorkerCredentialBoundary.NONE
    assert worker.runtime_boundary is WorkerRuntimeBoundary.OFFLINE_SANDBOX
    assert worker.required_identity_dimensions == ("analyzer", "artifact-digest")
    assert worker.required_budget_dimensions == ("artifact-bytes", "runtime")
    assert all(
        binding.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _BINDING_FALSE_MARKERS
    )
    classification = registered_application_static_analysis_capability_domain_classification()
    assert classification.domain_classification.domain is SecurityDomain.APPLICATION
    assert (
        resolve_application_static_analysis_capability_domain_classification(
            classification.reference()
        )
        == classification
    )
    assert resolve_application_static_analysis_binding(binding.reference()) == binding


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("toolId", "attacker.substituted-application-tool"),
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


def test_custody_binds_exact_surface_and_authorization_reference_without_artifact_access() -> None:
    surface = _surface(ApplicationSurfaceClass.LIBRARY)
    custody = _custody(surface)
    payload = custody.model_dump(mode="json", by_alias=True)

    assert custody.surface == surface
    assert custody.artifact_sha256 == surface.locator.artifact_sha256
    assert custody.artifact_bytes == 4_096
    assert custody.deployment_authorization_reference_bound is True
    assert all(payload[alias] is False for alias in _CUSTODY_FALSE_MARKERS)
    assert custody.custody_binding_id == (
        f"application-artifact-custody_{custody.custody_binding_digest}"
    )
    assert ApplicationArtifactCustodyBinding.model_validate(payload) == custody
    reference_payload = custody.reference().model_dump(mode="json", by_alias=True)
    reference_payload["custodyBindingId"] = f"application-artifact-custody_{'0' * 64}"
    with pytest.raises(ValidationError, match="reference identity differs"):
        ApplicationArtifactCustodyRef.model_validate(reference_payload)


def test_sandbox_pins_parser_digests_mount_and_resource_ceilings_without_runtime() -> None:
    sandbox = _sandbox(ApplicationStaticAnalysisOperation.BINARY_METADATA)
    payload = sandbox.model_dump(mode="json", by_alias=True)

    assert sandbox.parser is ApplicationStaticParser.BINARY_METADATA
    assert sandbox.artifact_mount_target == APPLICATION_ARTIFACT_MOUNT_TARGET
    assert sandbox.output_schema == APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA
    assert sandbox.run_as_identity == "svc:pajin-analyzer"
    assert sandbox.max_artifact_bytes == 65_536
    assert sandbox.max_output_bytes == 131_072
    assert sandbox.max_runtime_seconds == 30
    assert sandbox.max_memory_mib == 256
    assert sandbox.max_process_count == 4
    assert all(payload[alias] is False for alias in _SANDBOX_FALSE_MARKERS)
    assert sandbox.sandbox_binding_id == (
        f"application-static-analysis-sandbox_{sandbox.sandbox_binding_digest}"
    )
    assert ApplicationStaticAnalysisSandboxBinding.model_validate(payload) == sandbox
    reference_payload = sandbox.reference().model_dump(mode="json", by_alias=True)
    reference_payload["sandboxBindingId"] = f"application-static-analysis-sandbox_{'0' * 64}"
    with pytest.raises(ValidationError, match="reference identity differs"):
        ApplicationStaticAnalysisSandboxRef.model_validate(reference_payload)


@pytest.mark.parametrize("surface_class", tuple(ApplicationSurfaceClass))
def test_adapter_maps_each_surface_to_only_its_structure_parser(
    surface_class: ApplicationSurfaceClass,
) -> None:
    surface = _surface(surface_class)
    operation = _operation(surface)
    request = _adapter(surface).prepare_request(surface=surface, operation=operation)

    assert request.surface == surface
    assert request.operation is operation
    assert request.parser is request.sandbox.parser
    assert request.target == application_surface_scope_target(surface)
    assert request.method == "GET"
    assert request.output_schema == APPLICATION_STATIC_ANALYSIS_OUTPUT_SCHEMA
    assert request.budget.request_count == 1
    assert request.budget.artifact_bytes == 4_096
    assert request.budget.max_output_bytes == 131_072
    assert request.budget.runtime_seconds == 30
    assert request.budget.memory_mib == 256
    assert request.budget.process_count == 4
    assert request.budget.network_requests == 0
    assert request.budget.dynamic_target_executions == 0
    assert request.budget.debugger_attaches == 0
    assert request.budget.artifact_write_operations == 0
    assert request.budget.host_filesystem_reads == 0
    assert request.budget.credential_reads == 0
    assert (
        ApplicationStaticAnalysisRequest.model_validate(
            request.model_dump(mode="json", by_alias=True)
        )
        == request
    )


def test_signed_preparation_binds_scope_custody_sandbox_and_capability_without_dispatch(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    request = preparation.prepared_action.request
    payload = preparation.model_dump(mode="json", by_alias=True)

    assert preparation.state == "prepared-not-authorized"
    assert preparation.custody_authorization_reference_bound is True
    assert preparation.network_disabled_sandbox_bound is True
    assert preparation.matched_surface_allow_rule == application_surface_scope_target(
        preparation.surface
    )
    assert request.method == "GET"
    assert request.target == application_surface_scope_target(preparation.surface)
    assert request.arguments == preparation.analysis_request.model_dump(mode="json", by_alias=True)
    assert all(payload[alias] is False for alias in _PREPARATION_FALSE_MARKERS)
    assert preparation.preparation_id == (
        f"application-static-analysis-preparation_{preparation.preparation_digest}"
    )
    assert ApplicationStaticAnalysisPreparation.model_validate(payload) == preparation


def test_surface_custody_operation_and_parser_cannot_be_substituted() -> None:
    binary = _surface(ApplicationSurfaceClass.BINARY)
    library = _surface(ApplicationSurfaceClass.LIBRARY)
    adapter = _adapter(binary)

    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="Surface class"):
        adapter.prepare_request(
            surface=binary,
            operation=ApplicationStaticAnalysisOperation.LIBRARY_METADATA,
        )
    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="custody differs"):
        adapter.prepare_request(
            surface=library,
            operation=ApplicationStaticAnalysisOperation.LIBRARY_METADATA,
        )

    request_payload = adapter.prepare_request(
        surface=binary,
        operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
    ).model_dump(mode="json", by_alias=True)
    request_payload["parser"] = ApplicationStaticParser.LIBRARY_METADATA.value
    with pytest.raises(ValidationError, match="exact bindings"):
        ApplicationStaticAnalysisRequest.model_validate(request_payload)

    request_payload = deepcopy(request_payload)
    request_payload["parser"] = ApplicationStaticParser.BINARY_METADATA.value
    request_payload["custody"]["artifactSHA256"] = "0" * 64
    with pytest.raises(ValidationError, match="exact bindings"):
        ApplicationStaticAnalysisRequest.model_validate(request_payload)


def test_artifact_must_fit_exact_sandbox_ceiling() -> None:
    surface = _surface()
    adapter = _adapter(surface, artifact_bytes=65_537, max_artifact_bytes=65_536)
    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="artifact-byte ceiling"):
        adapter.prepare_request(
            surface=surface,
            operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
        )


@pytest.mark.parametrize(
    ("campaign_kwargs", "match"),
    (
        ({"include_surface": False}, "Application Surface lacks an exact"),
        ({"allow_get": False}, "reviewed GET authority"),
    ),
)
def test_preparation_requires_exact_surface_scope_and_get_authority(
    sample_campaign: CampaignManifest,
    campaign_kwargs: dict[str, bool],
    match: str,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(
        (ApplicationStaticAnalysisCapabilityError, ValidationError),
        match=match,
    ):
        prepare_application_static_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign, surface=surface, **campaign_kwargs),
            surface=surface,
            operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
            analyzer=_adapter(surface),
            request_id="tool_application_scope_rejected",
            agent_id="agent:application-static-analysis",
        )


def test_campaign_deny_overrides_exact_application_surface_allow(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    activation, release = _activation()
    target = application_surface_scope_target(surface)
    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="deny rule"):
        prepare_application_static_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign, surface=surface, deny=[target]),
            surface=surface,
            operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
            analyzer=_adapter(surface),
            request_id="tool_application_deny_rejected",
            agent_id="agent:application-static-analysis",
        )


def test_network_disabled_preparation_ignores_private_network_scope_flag(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    activation, release = _activation()
    preparation = prepare_application_static_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=surface, allow_private=True),
        surface=surface,
        operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
        analyzer=_adapter(surface),
        request_id="tool_application_network_disabled_prepare",
        agent_id="agent:application-static-analysis",
    )

    assert preparation.campaign_scope.allow_private_networks is True
    assert preparation.analysis_request.network_access_authorized is False
    assert preparation.analysis_request.budget.network_requests == 0


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
def test_sandbox_rejects_root_and_privileged_aliases(identity: str) -> None:
    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="non-root"):
        bind_application_static_analysis_sandbox(
            deployment_id="deployment:application-static-analysis",
            operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
            parser_executable_sha256=PARSER_DIGEST,
            sandbox_image_sha256=SANDBOX_IMAGE_DIGEST,
            run_as_identity=identity,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("maxArtifactBytes", 0),
        ("maxArtifactBytes", 536_870_913),
        ("maxArtifactBytes", True),
        ("maxOutputBytes", 1_023),
        ("maxOutputBytes", 16_777_217),
        ("maxRuntimeSeconds", 0),
        ("maxRuntimeSeconds", 301),
        ("maxMemoryMiB", 63),
        ("maxMemoryMiB", 4_097),
        ("maxProcessCount", 0),
        ("maxProcessCount", 65),
    ),
)
def test_sandbox_resource_ceiling_bounds_and_integer_types_fail_closed(
    field: str,
    value: int | bool,
) -> None:
    payload = _sandbox(ApplicationStaticAnalysisOperation.BINARY_METADATA).model_dump(
        mode="json", by_alias=True
    )
    payload[field] = value
    payload["sandboxBindingDigest"] = ""
    payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        ApplicationStaticAnalysisSandboxBinding.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("requestCount", 2),
        ("artifactBytes", 4_097),
        ("maxOutputBytes", 131_073),
        ("runtimeSeconds", 31),
        ("memoryMiB", 257),
        ("processCount", 5),
        ("networkRequests", 1),
        ("dynamicTargetExecutions", 1),
        ("debuggerAttaches", 1),
        ("artifactWriteOperations", 1),
        ("hostFilesystemReads", 1),
        ("credentialReads", 1),
    ),
)
def test_request_cannot_expand_execution_or_mutation_budget(field: str, value: int) -> None:
    surface = _surface()
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] = value
    with pytest.raises(ValidationError):
        ApplicationStaticAnalysisRequest.model_validate(payload)


def test_runtime_adapter_and_worker_job_remain_unavailable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    tool = ApplicationStaticAnalysisTool()
    activation = _activation()[0]
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    oracle = activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE)

    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="does not materialize"):
        tool.prepare(preparation.prepared_action.request)
    with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="does not materialize"):
        executor.prepare(preparation.prepared_action.request)
    assert (
        oracle.evaluate(
            preparation.prepared_action.request,
            ToolResult(
                request_id=preparation.prepared_action.request.request_id,
                tool_id=APPLICATION_STATIC_ANALYSIS_TOOL_ID,
                success=True,
                started_at=NOW,
                finished_at=NOW,
            ),
        )
        is CapabilityOracleDecision.INCONCLUSIVE
    )


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_application_static_analysis_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        ApplicationStaticAnalysisBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        ApplicationStaticAnalysisBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _CUSTODY_FALSE_MARKERS)
def test_custody_rejects_authority_escalation(alias: str) -> None:
    payload = _custody(_surface()).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["custodyBindingDigest"] = ""
    payload["custodyBindingId"] = ""
    with pytest.raises(ValidationError):
        ApplicationArtifactCustodyBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _SANDBOX_FALSE_MARKERS)
def test_sandbox_rejects_runtime_authority_escalation(alias: str) -> None:
    payload = _sandbox(ApplicationStaticAnalysisOperation.BINARY_METADATA).model_dump(
        mode="json", by_alias=True
    )
    payload[alias] = True
    payload["sandboxBindingDigest"] = ""
    payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        ApplicationStaticAnalysisSandboxBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _PREPARATION_FALSE_MARKERS)
def test_preparation_rejects_authority_escalation(
    alias: str,
    sample_campaign: CampaignManifest,
) -> None:
    payload = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["preparationDigest"] = ""
    payload["preparationId"] = ""
    with pytest.raises(ValidationError):
        ApplicationStaticAnalysisPreparation.model_validate(payload)


def test_preparation_rejects_surface_custody_sandbox_request_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("artifactCustody", "authorizationDigest", "0" * 64),
        ("artifactCustody", "artifactSHA256", "0" * 64),
        ("sandbox", "parserExecutableSHA256", "0" * 64),
        ("sandbox", "sandboxImageSHA256", "0" * 64),
        (
            "analysisRequest",
            "target",
            application_surface_scope_target(_surface(ApplicationSurfaceClass.LIBRARY)),
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
            ApplicationStaticAnalysisPreparation.model_validate(payload)


def test_stale_release_and_tool_request_substitution_fail_closed(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(ApplicationStaticAnalysisCapabilityError):
        prepare_application_static_analysis(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            campaign=_campaign(sample_campaign, surface=surface),
            surface=surface,
            operation=ApplicationStaticAnalysisOperation.BINARY_METADATA,
            analyzer=_adapter(surface),
            request_id="tool_application_stale_release",
            agent_id="agent:application-static-analysis",
        )

    request = _prepare(sample_campaign).prepared_action.request
    tool = ApplicationStaticAnalysisTool()
    for changed in (
        request.model_copy(update={"target": "https://other.example.test/v1/analyze"}),
        request.model_copy(update={"method": "POST"}),
    ):
        with pytest.raises(ApplicationStaticAnalysisCapabilityError, match="bounded GET"):
            tool.prepare(changed)


def test_custody_sandbox_and_request_reject_paths_secrets_and_runtime_admission() -> None:
    surface = _surface()
    custody_payload = _custody(surface).model_dump(mode="json", by_alias=True)
    for field, value in (
        ("artifactPath", "C:\\apps\\pajin.exe"),
        ("downloadURL", "https://artifacts.example.test/pajin.exe"),
        ("bearerToken", "secret-token"),
        ("artifactContent", "base64-data"),
    ):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ApplicationArtifactCustodyBinding.model_validate({**custody_payload, field: value})

    sandbox_payload = _sandbox(_operation(surface)).model_dump(mode="json", by_alias=True)
    for field, value in (
        ("networkEndpoint", "https://sandbox.example.test"),
        ("credential", {"token": "secret"}),
        ("workerAdmission", {"runtimeAttested": True}),
    ):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ApplicationStaticAnalysisSandboxBinding.model_validate(
                {**sandbox_payload, field: value}
            )

    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_operation(surface),
    )
    request_payload = request.model_dump(mode="json", by_alias=True)
    for field, value in (
        ("artifactContent", "base64-data"),
        ("credential", "secret-token"),
        ("sandboxAdmission", {"executionAuthorized": True}),
    ):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ApplicationStaticAnalysisRequest.model_validate({**request_payload, field: value})
