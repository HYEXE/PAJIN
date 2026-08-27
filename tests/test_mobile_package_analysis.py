from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import cache
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
from pajin.capabilities.mobile_package_analysis import (
    MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ID,
    MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA,
    MOBILE_PACKAGE_ANALYSIS_TOOL_ID,
    MOBILE_PACKAGE_MOUNT_TARGET,
    BoundedMobilePackageAnalyzerAdapter,
    MobilePackageAnalysisBinding,
    MobilePackageAnalysisBudget,
    MobilePackageAnalysisCapabilityActivation,
    MobilePackageAnalysisCapabilityError,
    MobilePackageAnalysisOperation,
    MobilePackageAnalysisPreparation,
    MobilePackageAnalysisRequest,
    MobilePackageAnalysisSandboxBinding,
    MobilePackageAnalysisSandboxRef,
    MobilePackageAnalysisTool,
    MobilePackageCustodyBinding,
    MobilePackageCustodyRef,
    MobilePackageParser,
    activate_mobile_package_analysis_capability,
    bind_mobile_package_analysis_sandbox,
    bind_mobile_package_custody,
    mobile_package_analysis_capability_bundle,
    mobile_surface_scope_target,
    prepare_mobile_package_analysis,
    registered_mobile_package_analysis_binding,
    registered_mobile_package_analysis_capability_definition,
    registered_mobile_package_analysis_capability_domain_classification,
    resolve_mobile_package_analysis_binding,
    resolve_mobile_package_analysis_capability_domain_classification,
)
from pajin.capabilities.models import CapabilityMaturity, CapabilitySideEffectClass
from pajin.discovery import (
    MobileAPKSurfaceLocator,
    MobileApplicationRuntimeSurface,
    MobileApplicationRuntimeSurfaceLocator,
    MobileApplicationSurfaceLocator,
    MobileAuthenticationKind,
    MobileDeepLinkKind,
    MobileIPASurfaceLocator,
    MobilePlatform,
    MobileRuntimeDeclarationKind,
    MobileStorageKind,
    MobileSurfaceClass,
    MobileTLSPolicyKind,
    mobile_apk_surface_locator,
    mobile_application_surface_locator,
    mobile_authentication_surface_locator,
    mobile_deep_link_surface_locator,
    mobile_ipa_surface_locator,
    mobile_runtime_surface_locator,
    mobile_storage_surface_locator,
    mobile_tls_policy_surface_locator,
    typed_mobile_application_runtime_surface,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
AUTHORIZATION_DIGEST = sha256(b"mobile-package-custody-authorization").hexdigest()
PARSER_DIGEST = sha256(b"mobile-package-static-parser").hexdigest()
SANDBOX_IMAGE_DIGEST = sha256(b"mobile-package-static-sandbox").hexdigest()

_BINDING_FALSE_MARKERS = (
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "custodyRuntimeVerified",
    "packageResolved",
    "packageReadAuthorized",
    "staticAnalysisAuthorized",
    "sandboxSelected",
    "workerSelectionAuthorized",
    "workerJobMaterializationAvailable",
    "packageMountMaterialized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorSelectionAuthorized",
    "deviceSelectionAuthorized",
    "deviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
    "packageMutationAuthorized",
    "observationProductionAuthorized",
    "evidenceSealingAuthorized",
    "graphAdmissionAuthorized",
    "hypothesisAuthority",
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
    "domainWorkerProfileBound",
    "deviceBoundRuntimeProfileApplied",
    "hostFilesystemAccessAllowed",
    "credentialInjectionAllowed",
    "environmentInheritanceAllowed",
    "symlinkTraversalAllowed",
    "runtimeAttested",
    "sandboxSelected",
    "artifactMountMaterialized",
    "artifactReadAuthorized",
    "workerSelectionAuthorized",
    "workerJobMaterializationAvailable",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorSelectionAuthorized",
    "deviceSelectionAuthorized",
    "deviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_PREPARATION_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "authorizationVerifiedByPreparation",
    "packageResolved",
    "packageBytesVerified",
    "packageFormatVerified",
    "manifestVerified",
    "signingIdentityVerified",
    "packageReadPerformed",
    "sandboxRuntimeAvailable",
    "sandboxRuntimeAttested",
    "sandboxSelected",
    "packageMountMaterialized",
    "budgetReserved",
    "domainWorkerProfileBound",
    "workerJobMaterialized",
    "networkRequestPerformed",
    "dnsRequestPerformed",
    "emulatorOrDeviceSelected",
    "packageInstalled",
    "applicationLaunched",
    "instrumentationPerformed",
    "dynamicTargetExecutionPerformed",
    "storageReadPerformed",
    "tlsInvocationPerformed",
    "authenticationInvocationPerformed",
    "credentialReadPerformed",
    "packageMutated",
    "observationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "hypothesisProduced",
    "findingProduced",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "executionAuthorized",
)
_BUDGET_ZERO_FIELDS = (
    "networkRequests",
    "dnsRequests",
    "packageInstallations",
    "applicationLaunches",
    "emulatorSessions",
    "deviceSessions",
    "instrumentationSessions",
    "dynamicTargetExecutions",
    "debuggerAttaches",
    "storageReads",
    "tlsConnections",
    "authenticationInvocations",
    "packageWriteOperations",
    "hostFilesystemReads",
    "credentialReads",
)
_REQUEST_FALSE_MARKERS = (
    "rawPackageContentEmbedded",
    "rawManifestEmbedded",
    "signingMaterialEmbedded",
    "mutablePackagePathEmbedded",
    "routablePackageURLEmbedded",
    "credentialMaterialEmbedded",
    "deviceIdentityEmbedded",
    "packageResolutionPerformed",
    "packageReadPerformed",
    "packageMountMaterialized",
    "sandboxInvocationAuthorized",
    "workerJobMaterializationAvailable",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "emulatorSelectionAuthorized",
    "deviceSelectionAuthorized",
    "deviceAccessAuthorized",
    "packageInstallationAuthorized",
    "applicationLaunchAuthorized",
    "instrumentationAuthorized",
    "dynamicTargetExecutionAuthorized",
    "storageReadAuthorized",
    "tlsInvocationAuthorized",
    "authenticationInvocationAuthorized",
    "credentialAccessAuthorized",
)


def _seed(label: str) -> bytes:
    return sha256(f"mobile-package-analysis:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"mobile-package-analysis.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


@cache
def _activation() -> tuple[MobilePackageAnalysisCapabilityActivation, CapabilityReleaseRef]:
    tools = ToolRegistry()
    tools.register(MobilePackageAnalysisTool())
    bundle = mobile_package_analysis_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="mobile-package-analysis.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="mobile-package-analysis.reviewer",
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
        checklistDigest=sha256(b"mobile-package-analysis-review").hexdigest(),
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
        activate_mobile_package_analysis_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


@cache
def _package_locator(
    platform: MobilePlatform,
    digest: str = "1" * 64,
) -> MobileAPKSurfaceLocator | MobileIPASurfaceLocator:
    if platform is MobilePlatform.ANDROID:
        return mobile_apk_surface_locator(artifact_sha256=digest)
    return mobile_ipa_surface_locator(artifact_sha256=digest)


def _application_locator(
    platform: MobilePlatform,
    digest: str = "1" * 64,
) -> MobileApplicationSurfaceLocator:
    return mobile_application_surface_locator(
        parent=_package_locator(platform, digest),
        application_id=(
            "dev.pajin.mobile" if platform is MobilePlatform.ANDROID else "dev.pajin.mobile-ios"
        ),
    )


@cache
def _surface(
    surface_class: MobileSurfaceClass = MobileSurfaceClass.APK,
    *,
    platform: MobilePlatform | None = None,
    digest: str = "1" * 64,
    variant: str = "primary",
) -> MobileApplicationRuntimeSurface:
    if surface_class is MobileSurfaceClass.APK:
        selected_platform = MobilePlatform.ANDROID
    elif surface_class is MobileSurfaceClass.IPA:
        selected_platform = MobilePlatform.IOS
    else:
        selected_platform = platform or MobilePlatform.ANDROID
    package = _package_locator(selected_platform, digest)
    application = mobile_application_surface_locator(
        parent=package,
        application_id=(
            f"dev.pajin.{variant}"
            if selected_platform is MobilePlatform.ANDROID
            else f"dev.pajin.{variant}-ios"
        ),
    )
    if surface_class in {MobileSurfaceClass.APK, MobileSurfaceClass.IPA}:
        locator: MobileApplicationRuntimeSurfaceLocator = package
    elif surface_class is MobileSurfaceClass.APPLICATION:
        locator = application
    elif surface_class is MobileSurfaceClass.RUNTIME:
        locator = mobile_runtime_surface_locator(
            parent=application,
            runtime_family=selected_platform,
            declaration_kind=MobileRuntimeDeclarationKind.TARGET,
            runtime_version="34" if selected_platform is MobilePlatform.ANDROID else "17.5",
        )
    elif surface_class is MobileSurfaceClass.STORAGE:
        locator = mobile_storage_surface_locator(
            parent=application,
            storage_kind=MobileStorageKind.PREFERENCES,
            storage_id=f"{variant}-preferences",
            declaration_sha256="3" * 64,
        )
    elif surface_class is MobileSurfaceClass.DEEPLINK:
        locator = mobile_deep_link_surface_locator(
            parent=application,
            link_kind=(
                MobileDeepLinkKind.ANDROID_APP_LINK
                if selected_platform is MobilePlatform.ANDROID
                else MobileDeepLinkKind.IOS_UNIVERSAL_LINK
            ),
            scheme="https",
            host="app.example.test",
            route_id=f"{variant}-route",
            declaration_sha256="4" * 64,
        )
    elif surface_class is MobileSurfaceClass.TLS:
        locator = mobile_tls_policy_surface_locator(
            parent=application,
            policy_kind=(
                MobileTLSPolicyKind.ANDROID_NETWORK_SECURITY_CONFIG
                if selected_platform is MobilePlatform.ANDROID
                else MobileTLSPolicyKind.IOS_APP_TRANSPORT_SECURITY
            ),
            policy_id=f"{variant}-tls",
            declaration_sha256="5" * 64,
        )
    else:
        locator = mobile_authentication_surface_locator(
            parent=application,
            authentication_kind=MobileAuthenticationKind.FEDERATED,
            flow_id=f"{variant}-login",
            declaration_sha256="6" * 64,
        )
    return typed_mobile_application_runtime_surface(locator=locator)


def _operation(surface: MobileApplicationRuntimeSurface) -> MobilePackageAnalysisOperation:
    return {
        MobileSurfaceClass.APK: MobilePackageAnalysisOperation.APK_PACKAGE_STRUCTURE,
        MobileSurfaceClass.IPA: MobilePackageAnalysisOperation.IPA_PACKAGE_STRUCTURE,
        MobileSurfaceClass.APPLICATION: (MobilePackageAnalysisOperation.APPLICATION_DECLARATION),
        MobileSurfaceClass.RUNTIME: MobilePackageAnalysisOperation.RUNTIME_DECLARATION,
        MobileSurfaceClass.STORAGE: MobilePackageAnalysisOperation.STORAGE_DECLARATION,
        MobileSurfaceClass.DEEPLINK: MobilePackageAnalysisOperation.DEEP_LINK_DECLARATION,
        MobileSurfaceClass.TLS: MobilePackageAnalysisOperation.TLS_POLICY_DECLARATION,
        MobileSurfaceClass.AUTH: (MobilePackageAnalysisOperation.AUTHENTICATION_FLOW_DECLARATION),
    }[surface.surface_class]


def _expected_parser(surface: MobileApplicationRuntimeSurface) -> MobilePackageParser:
    locator = surface.locator
    if isinstance(locator, MobileAPKSurfaceLocator):
        return MobilePackageParser.ANDROID_APK_STRUCTURE
    if isinstance(locator, MobileIPASurfaceLocator):
        return MobilePackageParser.IOS_IPA_STRUCTURE
    parent = locator.parent
    package = (
        parent
        if isinstance(parent, (MobileAPKSurfaceLocator, MobileIPASurfaceLocator))
        else parent.parent
    )
    return (
        MobilePackageParser.ANDROID_APK_STRUCTURE
        if isinstance(package, MobileAPKSurfaceLocator)
        else MobilePackageParser.IOS_IPA_STRUCTURE
    )


@cache
def _custody(
    surface: MobileApplicationRuntimeSurface,
    *,
    artifact_bytes: int = 4_096,
) -> MobilePackageCustodyBinding:
    return bind_mobile_package_custody(
        surface=surface,
        custody_authority_id="deployment:mobile-packages",
        custody_object_id=f"object-{surface.surface_digest}",
        authorization_id="authorization-mobile-001b",
        authorization_digest=AUTHORIZATION_DIGEST,
        artifact_bytes=artifact_bytes,
    )


@cache
def _sandbox(
    surface: MobileApplicationRuntimeSurface,
    *,
    max_artifact_bytes: int = 65_536,
) -> MobilePackageAnalysisSandboxBinding:
    return bind_mobile_package_analysis_sandbox(
        deployment_id="deployment:mobile-package-analysis",
        surface=surface,
        operation=_operation(surface),
        parser_executable_sha256=PARSER_DIGEST,
        sandbox_image_sha256=SANDBOX_IMAGE_DIGEST,
        run_as_identity="svc:pajin-mobile-analyzer",
        max_artifact_bytes=max_artifact_bytes,
        max_output_bytes=131_072,
        max_runtime_seconds=30,
        max_memory_mib=256,
        max_process_count=4,
        max_archive_entries=2_000,
        max_total_uncompressed_bytes=33_554_432,
        max_single_uncompressed_bytes=8_388_608,
        max_archive_path_bytes=512,
        max_archive_nesting_depth=4,
        max_compression_ratio=50,
    )


@cache
def _adapter(
    surface: MobileApplicationRuntimeSurface,
    *,
    artifact_bytes: int = 4_096,
    max_artifact_bytes: int = 65_536,
) -> BoundedMobilePackageAnalyzerAdapter:
    return BoundedMobilePackageAnalyzerAdapter(
        _custody(surface, artifact_bytes=artifact_bytes),
        _sandbox(surface, max_artifact_bytes=max_artifact_bytes),
    )


@cache
def _root_package_surface(
    surface: MobileApplicationRuntimeSurface,
) -> MobileApplicationRuntimeSurface:
    locator = surface.locator
    if isinstance(locator, (MobileAPKSurfaceLocator, MobileIPASurfaceLocator)):
        package = locator
    elif isinstance(locator, MobileApplicationSurfaceLocator):
        package = locator.parent
    else:
        package = locator.parent.parent
    return typed_mobile_application_runtime_surface(locator=package)


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    surface: MobileApplicationRuntimeSurface,
    include_surface: bool = True,
    include_package: bool = True,
    allow_get: bool = True,
    allow_private: bool = False,
    deny: list[str] | None = None,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    allow: set[str] = set()
    if include_surface:
        allow.add(mobile_surface_scope_target(surface))
    if include_package:
        allow.add(mobile_surface_scope_target(_root_package_surface(surface)))
    payload["spec"]["scope"] = {
        "allow": sorted(allow) or ["https://unrelated.example.test/"],
        "deny": deny if deny is not None else [],
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
    surface: MobileApplicationRuntimeSurface | None = None,
) -> MobilePackageAnalysisPreparation:
    if surface is None:
        cached = _cached_default_preparation(sample_campaign.model_dump_json(by_alias=True))
        return cached.model_copy(deep=True)
    return _prepare_uncached(sample_campaign, surface)


@cache
def _cached_default_preparation(campaign_json: str) -> MobilePackageAnalysisPreparation:
    return _prepare_uncached(CampaignManifest.model_validate_json(campaign_json), _surface())


def _prepare_uncached(
    sample_campaign: CampaignManifest,
    surface: MobileApplicationRuntimeSurface,
) -> MobilePackageAnalysisPreparation:
    activation, release = _activation()
    return prepare_mobile_package_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=surface),
        surface=surface,
        operation=_operation(surface),
        analyzer=_adapter(surface),
        request_id="tool_mobile_package_analysis_prepare",
        agent_id="agent:mobile-package-analysis",
    )


def test_capability_binding_pins_eight_mobile_surfaces_without_worker_profile() -> None:
    definition = registered_mobile_package_analysis_capability_definition()
    binding = registered_mobile_package_analysis_binding()
    tools = ToolRegistry()
    tools.register(MobilePackageAnalysisTool())
    bundle = mobile_package_analysis_capability_bundle(tools)

    assert definition.capability_id == MOBILE_PACKAGE_ANALYSIS_CAPABILITY_ID
    assert definition.supported_surface_types == (
        "mobile-apk-package",
        "mobile-application",
        "mobile-authentication",
        "mobile-deeplink",
        "mobile-ipa-package",
        "mobile-runtime",
        "mobile-storage",
        "mobile-tls-policy",
    )
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is False
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert len(binding.supported_locators) == 8
    assert binding.capability == bundle.capability()
    assert binding.domain_worker_profile_bound is False
    assert binding.domain_worker_profile_binding_deferred is True
    assert binding.worker_job_materialization_available is False
    assert "worker_profile" not in MobilePackageAnalysisBinding.model_fields
    assert all(
        binding.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _BINDING_FALSE_MARKERS
    )

    classification = registered_mobile_package_analysis_capability_domain_classification()
    assert classification.domain_classification.domain is SecurityDomain.MOBILE
    assert classification.domain_worker_profile_bound is False
    assert (
        resolve_mobile_package_analysis_capability_domain_classification(classification.reference())
        == classification
    )
    assert resolve_mobile_package_analysis_binding(binding.reference()) == binding


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("toolId", "attacker.substituted-mobile-tool"),
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


@pytest.mark.parametrize(
    ("surface_class", "platform"),
    (
        (MobileSurfaceClass.APK, MobilePlatform.ANDROID),
        (MobileSurfaceClass.IPA, MobilePlatform.IOS),
        *tuple(
            (surface_class, platform)
            for surface_class in tuple(MobileSurfaceClass)[2:]
            for platform in tuple(MobilePlatform)
        ),
    ),
)
def test_all_mobile_surfaces_bind_complete_operation_and_root_package_parser(
    surface_class: MobileSurfaceClass,
    platform: MobilePlatform,
) -> None:
    surface = _surface(surface_class, platform=platform)
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_operation(surface),
    )

    assert request.operation is _operation(surface)
    assert request.parser is _expected_parser(surface)
    assert request.package_surface == _root_package_surface(surface)
    assert request.custody.package_surface == request.package_surface.reference()
    assert request.sandbox.package_surface == request.package_surface.reference()
    assert request.target == mobile_surface_scope_target(surface)
    assert request.package_target == mobile_surface_scope_target(request.package_surface)
    assert request.method == "GET"
    assert request.output_schema == MOBILE_PACKAGE_ANALYSIS_OUTPUT_SCHEMA
    assert all(
        request.budget.model_dump(mode="json", by_alias=True)[field] == 0
        for field in _BUDGET_ZERO_FIELDS
    )


def test_custody_binds_selected_surface_root_package_and_opaque_authorization() -> None:
    surface = _surface(MobileSurfaceClass.AUTH, platform=MobilePlatform.IOS)
    custody = _custody(surface)
    payload = custody.model_dump(mode="json", by_alias=True)

    assert custody.surface == surface
    assert custody.package_surface == _root_package_surface(surface)
    assert custody.artifact_sha256 == "1" * 64
    assert custody.artifact_bytes == 4_096
    assert custody.exact_package_lineage_bound is True
    assert all(payload[alias] is False for alias in _CUSTODY_FALSE_MARKERS)
    assert custody.custody_binding_id == f"mobile-package-custody_{custody.custody_binding_digest}"
    assert MobilePackageCustodyBinding.model_validate(payload) == custody

    reference_payload = custody.reference().model_dump(mode="json", by_alias=True)
    reference_payload["custodyBindingId"] = f"mobile-package-custody_{'0' * 64}"
    with pytest.raises(ValidationError, match="reference identity differs"):
        MobilePackageCustodyRef.model_validate(reference_payload)


def test_sandbox_is_configuration_only_with_archive_bomb_and_device_boundaries() -> None:
    surface = _surface(MobileSurfaceClass.STORAGE, platform=MobilePlatform.IOS)
    sandbox = _sandbox(surface)
    payload = sandbox.model_dump(mode="json", by_alias=True)

    assert sandbox.surface == surface
    assert sandbox.package_surface == _root_package_surface(surface)
    assert sandbox.parser is MobilePackageParser.IOS_IPA_STRUCTURE
    assert sandbox.artifact_mount_target == MOBILE_PACKAGE_MOUNT_TARGET
    assert sandbox.network_disabled_required is True
    assert sandbox.dns_disabled_required is True
    assert sandbox.archive_path_traversal_rejected is True
    assert sandbox.archive_symlinks_rejected is True
    assert sandbox.archive_duplicate_names_rejected is True
    assert sandbox.max_archive_entries == 2_000
    assert sandbox.max_total_uncompressed_bytes == 33_554_432
    assert sandbox.max_single_uncompressed_bytes == 8_388_608
    assert all(payload[alias] is False for alias in _SANDBOX_FALSE_MARKERS)
    assert MobilePackageAnalysisSandboxBinding.model_validate(payload) == sandbox


def test_signed_preparation_binds_both_scope_tokens_and_stops_before_dispatch(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(MobileSurfaceClass.DEEPLINK, platform=MobilePlatform.IOS)
    preparation = _prepare(sample_campaign, surface=surface)
    request = preparation.prepared_action.request

    assert preparation.state == "prepared-not-authorized"
    assert preparation.package_surface == _root_package_surface(surface)
    assert preparation.matched_surface_allow_rule == mobile_surface_scope_target(surface)
    assert preparation.matched_package_allow_rule == mobile_surface_scope_target(
        preparation.package_surface
    )
    assert preparation.analysis_request.target == mobile_surface_scope_target(surface)
    assert request.arguments == preparation.analysis_request.model_dump(
        mode="json",
        by_alias=True,
    )
    assert preparation.domain_worker_profile_bound is False
    assert preparation.worker_job_materialized is False
    assert all(
        preparation.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _PREPARATION_FALSE_MARKERS
    )


@pytest.mark.parametrize(
    ("include_surface", "include_package", "allow_get"),
    (
        (False, True, True),
        (True, False, True),
        (True, True, False),
    ),
)
def test_preparation_requires_selected_and_root_package_scope_and_get(
    sample_campaign: CampaignManifest,
    include_surface: bool,
    include_package: bool,
    allow_get: bool,
) -> None:
    surface = _surface(MobileSurfaceClass.AUTH)
    activation, release = _activation()
    with pytest.raises(MobilePackageAnalysisCapabilityError):
        prepare_mobile_package_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(
                sample_campaign,
                surface=surface,
                include_surface=include_surface,
                include_package=include_package,
                allow_get=allow_get,
            ),
            surface=surface,
            operation=_operation(surface),
            analyzer=_adapter(surface),
            request_id="tool_mobile_scope_rejected",
            agent_id="agent:mobile-package-analysis",
        )


def test_deny_overrides_scope_and_private_network_flag_does_not_open_network(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(MobileSurfaceClass.RUNTIME)
    package_target = mobile_surface_scope_target(_root_package_surface(surface))
    activation, release = _activation()

    with pytest.raises(MobilePackageAnalysisCapabilityError, match="deny"):
        prepare_mobile_package_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(
                sample_campaign,
                surface=surface,
                deny=[package_target],
            ),
            surface=surface,
            operation=_operation(surface),
            analyzer=_adapter(surface),
            request_id="tool_mobile_scope_denied",
            agent_id="agent:mobile-package-analysis",
        )

    preparation = prepare_mobile_package_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(
            sample_campaign,
            surface=surface,
            allow_private=True,
        ),
        surface=surface,
        operation=_operation(surface),
        analyzer=_adapter(surface),
        request_id="tool_mobile_private_scope",
        agent_id="agent:mobile-package-analysis",
    )
    assert preparation.campaign_scope.allow_private_networks is True
    assert preparation.analysis_request.budget.network_requests == 0
    assert preparation.analysis_request.budget.dns_requests == 0
    assert preparation.analysis_request.device_access_authorized is False


def test_same_digest_apk_ipa_child_and_parser_substitution_fail_closed() -> None:
    digest = "a" * 64
    apk = _surface(MobileSurfaceClass.APPLICATION, platform=MobilePlatform.ANDROID, digest=digest)
    ipa = _surface(MobileSurfaceClass.APPLICATION, platform=MobilePlatform.IOS, digest=digest)
    other_child = _surface(
        MobileSurfaceClass.APPLICATION,
        platform=MobilePlatform.ANDROID,
        digest=digest,
        variant="other",
    )

    with pytest.raises(MobilePackageAnalysisCapabilityError):
        BoundedMobilePackageAnalyzerAdapter(_custody(apk), _sandbox(ipa))
    with pytest.raises(MobilePackageAnalysisCapabilityError):
        BoundedMobilePackageAnalyzerAdapter(_custody(apk), _sandbox(other_child))

    request = _adapter(apk).prepare_request(surface=apk, operation=_operation(apk))
    payload = request.model_dump(mode="json", by_alias=True)
    payload["parser"] = MobilePackageParser.IOS_IPA_STRUCTURE.value
    with pytest.raises(ValidationError):
        MobilePackageAnalysisRequest.model_validate(payload)


def test_operation_and_sandbox_surface_substitution_fail_closed() -> None:
    surface = _surface(MobileSurfaceClass.STORAGE)
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="operation differs"):
        bind_mobile_package_analysis_sandbox(
            deployment_id="deployment:mobile-package-analysis",
            surface=surface,
            operation=MobilePackageAnalysisOperation.RUNTIME_DECLARATION,
            parser_executable_sha256=PARSER_DIGEST,
            sandbox_image_sha256=SANDBOX_IMAGE_DIGEST,
            run_as_identity="svc:pajin-mobile-analyzer",
        )

    other = _surface(MobileSurfaceClass.STORAGE, variant="other")
    adapter = _adapter(surface)
    with pytest.raises(MobilePackageAnalysisCapabilityError):
        adapter.prepare_request(surface=other, operation=_operation(other))


@pytest.mark.parametrize(
    "identity",
    (
        "root",
        "ROOT",
        "uid:0",
        "uid-000",
        "S-1-5-18",
        "S-1-5-21-1-2-3-500",
        "Administrator",
        "system:service",
    ),
)
def test_sandbox_rejects_root_and_privileged_identities(identity: str) -> None:
    surface = _surface()
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="non-root"):
        bind_mobile_package_analysis_sandbox(
            deployment_id="deployment:mobile-package-analysis",
            surface=surface,
            operation=_operation(surface),
            parser_executable_sha256=PARSER_DIGEST,
            sandbox_image_sha256=SANDBOX_IMAGE_DIGEST,
            run_as_identity=identity,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_archive_entries", True),
        ("max_total_uncompressed_bytes", 0),
        ("max_single_uncompressed_bytes", 268_435_457),
        ("max_archive_path_bytes", 0),
        ("max_archive_nesting_depth", 33),
        ("max_compression_ratio", 1_001),
    ),
)
def test_archive_resource_ceilings_and_exact_integer_types_fail_closed(
    field: str,
    value: object,
) -> None:
    surface = _surface()
    kwargs: dict[str, object] = {
        "deployment_id": "deployment:mobile-package-analysis",
        "surface": surface,
        "operation": _operation(surface),
        "parser_executable_sha256": PARSER_DIGEST,
        "sandbox_image_sha256": SANDBOX_IMAGE_DIGEST,
        "run_as_identity": "svc:pajin-mobile-analyzer",
        field: value,
    }
    with pytest.raises(MobilePackageAnalysisCapabilityError):
        bind_mobile_package_analysis_sandbox(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", _BUDGET_ZERO_FIELDS)
def test_request_cannot_expand_live_or_mutating_budget(field: str) -> None:
    surface = _surface()
    request = _adapter(surface).prepare_request(surface=surface, operation=_operation(surface))
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] = 1
    with pytest.raises(ValidationError):
        MobilePackageAnalysisRequest.model_validate(payload)

    payload["budget"][field] = True
    with pytest.raises(ValidationError, match="must be integers"):
        MobilePackageAnalysisRequest.model_validate(payload)


def test_request_rejects_authority_escalation_and_boolean_coercion() -> None:
    surface = _surface()
    original = (
        _adapter(surface)
        .prepare_request(surface=surface, operation=_operation(surface))
        .model_dump(mode="json", by_alias=True)
    )
    for alias in _REQUEST_FALSE_MARKERS:
        payload = deepcopy(original)
        payload[alias] = True
        with pytest.raises(ValidationError):
            MobilePackageAnalysisRequest.model_validate(payload)

        payload[alias] = 0
        with pytest.raises(ValidationError, match="must be booleans"):
            MobilePackageAnalysisRequest.model_validate(payload)


def test_runtime_adapter_worker_job_and_result_normalizer_remain_unavailable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    tool = MobilePackageAnalysisTool()
    activation = _activation()[0]
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    normalizer = activation.authority(CapabilityAuthorityRole.RESULT_NORMALIZER)
    oracle = activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE)
    replay = activation.authority(CapabilityAuthorityRole.REPLAY_STRATEGY)
    cleanup = activation.authority(CapabilityAuthorityRole.CLEANUP_HANDLER)
    result = ToolResult(
        request_id=preparation.prepared_action.request.request_id,
        tool_id=MOBILE_PACKAGE_ANALYSIS_TOOL_ID,
        success=True,
        started_at=NOW,
        finished_at=NOW,
    )
    worker_result = WorkerResult(
        execution_id="mobile-package-analysis-execution",
        backend="unavailable-mobile-package-analyzer",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=NOW,
        finished_at=NOW,
    )

    with pytest.raises(MobilePackageAnalysisCapabilityError, match="does not materialize"):
        tool.prepare(preparation.prepared_action.request)
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="does not materialize"):
        executor.prepare(preparation.prepared_action.request)
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="no sandbox result"):
        normalizer.normalize(preparation.prepared_action.request, worker_result)
    assert (
        oracle.evaluate(preparation.prepared_action.request, result)
        is CapabilityOracleDecision.INCONCLUSIVE
    )
    assert replay.plan_replay(preparation.prepared_action.request, result) is None
    assert cleanup.plan_cleanup(preparation.prepared_action.request, result) is None


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_mobile_package_analysis_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        MobilePackageAnalysisBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        MobilePackageAnalysisBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _CUSTODY_FALSE_MARKERS)
def test_custody_rejects_authority_escalation(alias: str) -> None:
    payload = _custody(_surface()).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["custodyBindingDigest"] = ""
    payload["custodyBindingId"] = ""
    with pytest.raises(ValidationError):
        MobilePackageCustodyBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _SANDBOX_FALSE_MARKERS)
def test_sandbox_rejects_runtime_authority_escalation(alias: str) -> None:
    payload = _sandbox(_surface()).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["sandboxBindingDigest"] = ""
    payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        MobilePackageAnalysisSandboxBinding.model_validate(payload)


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
        MobilePackageAnalysisPreparation.model_validate(payload)


def test_preparation_rejects_custody_sandbox_scope_release_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("packageCustody", "authorizationDigest", "0" * 64),
        ("packageCustody", "artifactSHA256", "0" * 64),
        ("sandbox", "parserExecutableSHA256", "0" * 64),
        ("sandbox", "sandboxImageSHA256", "0" * 64),
        ("campaignScope", "campaignDigest", "0" * 64),
        ("preparedAction", "requestDigest", "0" * 64),
        (None, "preparationDigest", "0" * 64),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            MobilePackageAnalysisPreparation.model_validate(payload)


def test_stale_release_and_tool_request_substitution_fail_closed(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(MobilePackageAnalysisCapabilityError):
        prepare_mobile_package_analysis(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            campaign=_campaign(sample_campaign, surface=surface),
            surface=surface,
            operation=_operation(surface),
            analyzer=_adapter(surface),
            request_id="tool_mobile_stale_release",
            agent_id="agent:mobile-package-analysis",
        )

    request = _prepare(sample_campaign).prepared_action.request
    tool = MobilePackageAnalysisTool()
    for changed in (
        request.model_copy(update={"target": "https://other.example.test/v1/analyze"}),
        request.model_copy(update={"method": "POST"}),
    ):
        with pytest.raises(MobilePackageAnalysisCapabilityError):
            tool.prepare(changed)


def test_models_reject_paths_urls_secrets_device_ids_and_runtime_admission() -> None:
    surface = _surface()
    custody_payload = _custody(surface).model_dump(mode="json", by_alias=True)
    custody_injections: tuple[tuple[str, object], ...] = (
        ("packagePath", r"C:\packages\pajin.apk"),
        ("downloadURL", "https://artifacts.example.test/pajin.apk"),
        ("bearerToken", "secret-token"),
        ("packageContent", "base64-data"),
        ("deviceId", "device-123"),
    )
    for field, value in custody_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            MobilePackageCustodyBinding.model_validate({**custody_payload, field: value})

    sandbox_payload = _sandbox(surface).model_dump(mode="json", by_alias=True)
    sandbox_injections: tuple[tuple[str, object], ...] = (
        ("networkEndpoint", "https://sandbox.example.test"),
        ("credential", {"token": "secret"}),
        ("deviceIdentity", "device-123"),
        ("emulatorIdentity", "emulator-123"),
        ("workerAdmission", {"runtimeAttested": True}),
    )
    for field, value in sandbox_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            MobilePackageAnalysisSandboxBinding.model_validate({**sandbox_payload, field: value})

    request_payload = (
        _adapter(surface)
        .prepare_request(
            surface=surface,
            operation=_operation(surface),
        )
        .model_dump(mode="json", by_alias=True)
    )
    request_injections: tuple[tuple[str, object], ...] = (
        ("manifest", {"package": "dev.pajin.mobile"}),
        ("signingCertificate", "certificate-data"),
        ("credentialLease", {"leaseId": "lease-1"}),
        ("deviceSession", {"deviceId": "device-123"}),
        ("endpoint", "https://api.example.test"),
    )
    for field, value in request_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            MobilePackageAnalysisRequest.model_validate({**request_payload, field: value})


def test_forged_model_copy_instance_state_fails_at_public_boundaries(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(MobileSurfaceClass.AUTH)
    forged_surface = surface.model_copy(update={"deviceToken": "secret"})
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="unmodeled"):
        _custody(forged_surface)

    custody = _custody(surface)
    forged_custody = custody.model_copy(update={"bearerToken": "secret"})
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="unmodeled"):
        BoundedMobilePackageAnalyzerAdapter(forged_custody, _sandbox(surface))

    forged_nested = custody.model_copy(
        update={"surface": surface.model_copy(update={"emulatorId": "emulator-1"})}
    )
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="unmodeled"):
        BoundedMobilePackageAnalyzerAdapter(forged_nested, _sandbox(surface))

    binding_ref = registered_mobile_package_analysis_binding().reference()
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="unmodeled"):
        resolve_mobile_package_analysis_binding(binding_ref.model_copy(update={"secret": "token"}))

    classification = registered_mobile_package_analysis_capability_domain_classification()
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="unmodeled"):
        resolve_mobile_package_analysis_capability_domain_classification(
            classification.reference().model_copy(update={"deviceId": "device-1"})
        )

    request = _prepare(sample_campaign).prepared_action.request
    with pytest.raises(MobilePackageAnalysisCapabilityError, match="unmodeled"):
        MobilePackageAnalysisTool().prepare(request.model_copy(update={"credential": "secret"}))


def test_reference_and_request_models_reject_parser_package_and_ceiling_drift() -> None:
    surface = _surface(MobileSurfaceClass.RUNTIME, platform=MobilePlatform.IOS)
    request = _adapter(surface).prepare_request(surface=surface, operation=_operation(surface))

    custody_ref = request.custody.model_dump(mode="json", by_alias=True)
    custody_ref["packageSurface"] = (
        _surface()
        .reference()
        .model_dump(
            mode="json",
            by_alias=True,
        )
    )
    with pytest.raises(ValidationError):
        MobilePackageCustodyRef.model_validate(custody_ref)

    sandbox_ref = request.sandbox.model_dump(mode="json", by_alias=True)
    sandbox_ref["parser"] = MobilePackageParser.ANDROID_APK_STRUCTURE.value
    with pytest.raises(ValidationError):
        MobilePackageAnalysisSandboxRef.model_validate(sandbox_ref)

    sandbox_ref = request.sandbox.model_dump(mode="json", by_alias=True)
    sandbox_ref["maxSingleUncompressedBytes"] = sandbox_ref["maxTotalUncompressedBytes"] + 1
    with pytest.raises(ValidationError):
        MobilePackageAnalysisSandboxRef.model_validate(sandbox_ref)


def test_reference_digests_reject_request_summary_and_cross_platform_identity_drift() -> None:
    surface = _surface(MobileSurfaceClass.APPLICATION)
    request = _adapter(surface).prepare_request(surface=surface, operation=_operation(surface))
    original = request.model_dump(mode="json", by_alias=True)
    mutations: tuple[tuple[str, str, object], ...] = (
        ("custody", "authorizationDigest", "0" * 64),
        ("custody", "custodyObjectId", "object-mutated"),
        ("sandbox", "parserExecutableSHA256", "0" * 64),
        ("sandbox", "sandboxImageSHA256", "0" * 64),
        ("sandbox", "deploymentId", "deployment:mobile-package-analysis-mutated"),
        ("sandbox", "maxArchiveEntries", request.sandbox.max_archive_entries + 1),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        payload[parent][key] = value
        with pytest.raises(ValidationError):
            MobilePackageAnalysisRequest.model_validate(payload)

    ios_surface = _surface(MobileSurfaceClass.APPLICATION, platform=MobilePlatform.IOS)
    ios_request = _adapter(ios_surface).prepare_request(
        surface=ios_surface,
        operation=_operation(ios_surface),
    )
    ios_payload = ios_request.model_dump(mode="json", by_alias=True)
    cross_platform = deepcopy(original)
    for key in ("surface", "packageSurface", "target", "packageTarget", "parser"):
        cross_platform[key] = ios_payload[key]
    for parent in ("custody", "sandbox"):
        cross_platform[parent]["surface"] = ios_payload[parent]["surface"]
        cross_platform[parent]["packageSurface"] = ios_payload[parent]["packageSurface"]
    cross_platform["sandbox"]["parser"] = ios_payload["sandbox"]["parser"]
    with pytest.raises(ValidationError):
        MobilePackageAnalysisRequest.model_validate(cross_platform)


def test_capability_materializer_rejects_mutated_reference_summary() -> None:
    surface = _surface(MobileSurfaceClass.APPLICATION)
    analysis = _adapter(surface).prepare_request(surface=surface, operation=_operation(surface))
    parameters = analysis.model_dump(mode="json", by_alias=True)
    parameters["custody"]["authorizationDigest"] = "0" * 64
    activation, release = _activation()
    request = ToolRequest(
        request_id="tool_mobile_mutated_reference",
        agent_id="agent:mobile-package-analysis",
        tool_id=MOBILE_PACKAGE_ANALYSIS_TOOL_ID,
        target=analysis.target,
        method="GET",
        arguments={},
    )
    with pytest.raises(MobilePackageAnalysisCapabilityError):
        activation.prepare_action(
            release=release,
            request=request,
            parameters=parameters,
        )


def test_budget_and_models_do_not_contain_runtime_authority_fields() -> None:
    forbidden = {
        "device_id",
        "emulator_id",
        "adb_endpoint",
        "simctl_endpoint",
        "usbmuxd_endpoint",
        "credential",
        "token",
        "package_path",
        "package_url",
        "worker_job",
        "permit",
        "observation",
        "evidence",
        "finding",
    }
    assert forbidden.isdisjoint(MobilePackageAnalysisBudget.model_fields)
    assert forbidden.isdisjoint(MobilePackageAnalysisRequest.model_fields)
    assert forbidden.isdisjoint(MobilePackageAnalysisPreparation.model_fields)
