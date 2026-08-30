from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import cache
from hashlib import sha256
from inspect import signature

import pytest
from pydantic import ValidationError

from pajin.capabilities.authorities import CapabilityAuthorityRole, CapabilityOracleDecision
from pajin.capabilities.cryptographic_misuse_analysis import (
    CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_AUTHORITY_ID,
    CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_MOUNT_TARGET,
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ID,
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID,
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA,
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY,
    CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID,
    CRYPTOGRAPHIC_SURFACE_SCOPE_ORIGIN,
    BoundedCryptographicMisuseAnalyzerAdapter,
    CryptographicAnalysisArtifactCustodyBinding,
    CryptographicAnalysisArtifactCustodyRef,
    CryptographicAnalysisDigestSource,
    CryptographicAnalysisInputKind,
    CryptographicMisuseAnalysisBinding,
    CryptographicMisuseAnalysisBudget,
    CryptographicMisuseAnalysisCapabilityActivation,
    CryptographicMisuseAnalysisCapabilityError,
    CryptographicMisuseAnalysisOperation,
    CryptographicMisuseAnalysisPreparation,
    CryptographicMisuseAnalysisRequest,
    CryptographicMisuseAnalysisSandboxBinding,
    CryptographicMisuseAnalysisSandboxRef,
    CryptographicMisuseAnalysisTool,
    CryptographicMisuseAnalyzer,
    CryptographicMisuseSignalKind,
    CryptographicSurfaceAnalysisMapping,
    RegisteredCryptographicMisuseRuleSet,
    activate_cryptographic_misuse_analysis_capability,
    bind_cryptographic_analysis_artifact_custody,
    bind_cryptographic_misuse_analysis_sandbox,
    cryptographic_misuse_analysis_capability_bundle,
    cryptographic_surface_scope_target,
    prepare_cryptographic_misuse_analysis,
    registered_cryptographic_misuse_analysis_binding,
    registered_cryptographic_misuse_analysis_capability_definition,
    registered_cryptographic_misuse_analysis_capability_domain_classification,
    registered_cryptographic_misuse_rule_set,
    resolve_cryptographic_misuse_analysis_binding,
    resolve_cryptographic_misuse_analysis_capability_domain_classification,
    resolve_registered_cryptographic_misuse_rule_set,
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
from pajin.capabilities.models import (
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.discovery import (
    CryptographicCiphertextSurfaceLocator,
    CryptographicConfigurationSurfaceLocator,
    CryptographicKeyUsageKind,
    CryptographicKeyUsageSurfaceLocator,
    CryptographicProtocolSurfaceLocator,
    CryptographyProtocolKeyArtifactSurface,
    CryptographySurfaceClass,
    cryptographic_ciphertext_surface_locator,
    cryptographic_configuration_surface_locator,
    cryptographic_key_usage_surface_locator,
    cryptographic_protocol_surface_locator,
    typed_cryptography_protocol_key_artifact_surface,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.ctf import CTF_CRYPTO_XOR_TOOL_ID

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
AUTHORIZATION_DIGEST = sha256(b"cryptographic-custody-authorization").hexdigest()
ANALYZER_DIGEST = sha256(b"cryptographic-misuse-analyzer").hexdigest()
SANDBOX_IMAGE_DIGEST = sha256(b"cryptographic-misuse-sandbox-image").hexdigest()

_OPERATION_BY_CLASS = {
    CryptographySurfaceClass.PROTOCOL: (CryptographicMisuseAnalysisOperation.PROTOCOL_DECLARATION),
    CryptographySurfaceClass.KEY_USAGE: (
        CryptographicMisuseAnalysisOperation.KEY_USAGE_DECLARATION
    ),
    CryptographySurfaceClass.CIPHERTEXT: (
        CryptographicMisuseAnalysisOperation.CIPHERTEXT_STRUCTURE
    ),
    CryptographySurfaceClass.CONFIGURATION: (
        CryptographicMisuseAnalysisOperation.CONFIGURATION_DECLARATION
    ),
}
_ANALYZER_BY_CLASS = {
    CryptographySurfaceClass.PROTOCOL: CryptographicMisuseAnalyzer.PROTOCOL_DECLARATION,
    CryptographySurfaceClass.KEY_USAGE: CryptographicMisuseAnalyzer.KEY_USAGE_DECLARATION,
    CryptographySurfaceClass.CIPHERTEXT: CryptographicMisuseAnalyzer.CIPHERTEXT_STRUCTURE,
    CryptographySurfaceClass.CONFIGURATION: (CryptographicMisuseAnalyzer.CONFIGURATION_DECLARATION),
}
_INPUT_KIND_BY_CLASS = {
    CryptographySurfaceClass.PROTOCOL: (
        CryptographicAnalysisInputKind.SANITIZED_PROTOCOL_DECLARATION
    ),
    CryptographySurfaceClass.KEY_USAGE: (
        CryptographicAnalysisInputKind.SANITIZED_KEY_USAGE_DECLARATION
    ),
    CryptographySurfaceClass.CIPHERTEXT: CryptographicAnalysisInputKind.CIPHERTEXT_ARTIFACT,
    CryptographySurfaceClass.CONFIGURATION: (
        CryptographicAnalysisInputKind.SANITIZED_CONFIGURATION_DECLARATION
    ),
}
_LOCATOR_KIND_BY_CLASS = {
    CryptographySurfaceClass.PROTOCOL: "cryptography-protocol",
    CryptographySurfaceClass.KEY_USAGE: "cryptography-key-usage",
    CryptographySurfaceClass.CIPHERTEXT: "cryptography-ciphertext",
    CryptographySurfaceClass.CONFIGURATION: "cryptography-configuration",
}
_DIGEST_SOURCE_BY_CLASS = {
    CryptographySurfaceClass.PROTOCOL: CryptographicAnalysisDigestSource.DECLARATION_SHA256,
    CryptographySurfaceClass.KEY_USAGE: (CryptographicAnalysisDigestSource.DECLARATION_SHA256),
    CryptographySurfaceClass.CIPHERTEXT: CryptographicAnalysisDigestSource.ARTIFACT_SHA256,
    CryptographySurfaceClass.CONFIGURATION: (CryptographicAnalysisDigestSource.DECLARATION_SHA256),
}

_BINDING_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "authorizationVerified",
    "declarationSanitizationVerified",
    "artifactResolved",
    "artifactReadAuthorized",
    "misuseAnalysisAuthorized",
    "sandboxSelected",
    "workerSelectionAuthorized",
    "artifactMountMaterialized",
    "keyMaterialAccessAuthorized",
    "credentialUseAuthorized",
    "cryptographicOperationAuthorized",
    "keySearchAuthorized",
    "protocolNegotiationAuthorized",
    "oracleInvocationAuthorized",
    "networkAccessAuthorized",
    "artifactMutationAuthorized",
    "observationProductionAuthorized",
    "evidenceSealingAuthorized",
    "graphAdmissionAuthorized",
    "hypothesisAuthority",
    "findingAuthority",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "ctfRuntimeReused",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_CUSTODY_FALSE_MARKERS = (
    "rawArtifactContentEmbedded",
    "rawKeyMaterialEmbedded",
    "keyReferenceEmbedded",
    "rawPlaintextEmbedded",
    "rawConfigurationEmbedded",
    "mutablePathEmbedded",
    "secretMaterialEmbedded",
    "credentialReferenceEmbedded",
    "authorizationVerifiedByPreparation",
    "declarationSanitizationVerified",
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
    "keyMaterialInjectionAllowed",
    "environmentInheritanceAllowed",
    "symlinkTraversalAllowed",
    "deviceAccessAllowed",
    "pluginLoadingAllowed",
    "shellCommandAllowed",
    "runtimeAttested",
    "sandboxSelected",
    "artifactMountMaterialized",
    "artifactReadAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "dnsAccessAuthorized",
    "keyMaterialAccessAuthorized",
    "credentialUseAuthorized",
    "cryptographicOperationAuthorized",
    "keySearchAuthorized",
    "protocolNegotiationAuthorized",
    "oracleInvocationAuthorized",
    "rawResultEchoAllowed",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_REQUEST_FALSE_MARKERS = (
    "rawArtifactContentEmbedded",
    "rawKeyMaterialEmbedded",
    "keyReferenceEmbedded",
    "rawCiphertextEmbedded",
    "rawPlaintextEmbedded",
    "rawConfigurationEmbedded",
    "rawParameterMaterialEmbedded",
    "mutableArtifactPathEmbedded",
    "credentialMaterialEmbedded",
    "callerRuleOrPluginEmbedded",
    "artifactResolutionPerformed",
    "artifactReadPerformed",
    "artifactMountMaterialized",
    "sandboxInvocationAuthorized",
    "keyMaterialAccessAuthorized",
    "credentialUseAuthorized",
    "cryptographicOperationAuthorized",
    "keySearchAuthorized",
    "protocolNegotiationAuthorized",
    "oracleInvocationAuthorized",
    "networkAccessAuthorized",
    "misuseAnalysisExecuted",
)
_PREPARATION_FALSE_MARKERS = (
    "custodyRuntimeVerified",
    "authorizationVerifiedByPreparation",
    "declarationSanitizationVerified",
    "artifactResolved",
    "artifactBytesVerified",
    "artifactReadPerformed",
    "sandboxRuntimeAvailable",
    "sandboxRuntimeAttested",
    "sandboxSelected",
    "artifactMountMaterialized",
    "budgetReserved",
    "workerJobMaterialized",
    "keyMaterialAccessed",
    "credentialUsed",
    "cryptographicOperationPerformed",
    "keySearchPerformed",
    "protocolNegotiationPerformed",
    "oracleInvoked",
    "networkRequestPerformed",
    "misuseAnalysisExecuted",
    "artifactMutated",
    "observationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "hypothesisProduced",
    "findingProduced",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "ctfRuntimeReused",
    "executionAuthorized",
)
_BUDGET_ZERO_FIELDS = (
    "networkRequests",
    "dnsQueries",
    "hostFilesystemReads",
    "artifactWriteOperations",
    "credentialReads",
    "keyMaterialReads",
    "keyStoreSessions",
    "cryptographicOperations",
    "keySearchAttempts",
    "protocolNegotiations",
    "oracleInvocations",
    "plaintextOutputs",
    "keyMaterialOutputs",
    "targetProcessExecutions",
    "shellCommands",
)


def _seed(label: str) -> bytes:
    return sha256(f"cryptographic-misuse-analysis:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"cryptographic-misuse-analysis.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


@cache
def _activation() -> tuple[
    CryptographicMisuseAnalysisCapabilityActivation,
    CapabilityReleaseRef,
]:
    tools = ToolRegistry()
    tools.register(CryptographicMisuseAnalysisTool())
    bundle = cryptographic_misuse_analysis_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="cryptographic-misuse-analysis.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="cryptographic-misuse-analysis.reviewer",
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
        checklistDigest=sha256(b"cryptographic-misuse-analysis-review").hexdigest(),
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
        activate_cryptographic_misuse_analysis_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


def _surface(
    surface_class: CryptographySurfaceClass = CryptographySurfaceClass.PROTOCOL,
) -> CryptographyProtocolKeyArtifactSurface:
    protocol = cryptographic_protocol_surface_locator(
        protocol_namespace="ietf",
        protocol_id="tls-1.3",
        declaration_sha256="1" * 64,
    )
    locator: (
        CryptographicProtocolSurfaceLocator
        | CryptographicKeyUsageSurfaceLocator
        | CryptographicCiphertextSurfaceLocator
        | CryptographicConfigurationSurfaceLocator
    )
    if surface_class is CryptographySurfaceClass.PROTOCOL:
        locator = protocol
    elif surface_class is CryptographySurfaceClass.KEY_USAGE:
        locator = cryptographic_key_usage_surface_locator(
            parent=protocol,
            usage_kind=CryptographicKeyUsageKind.DECRYPTION,
            declaration_sha256="2" * 64,
        )
    elif surface_class is CryptographySurfaceClass.CIPHERTEXT:
        locator = cryptographic_ciphertext_surface_locator(
            parent=protocol,
            artifact_sha256="3" * 64,
        )
    else:
        locator = cryptographic_configuration_surface_locator(
            parent=protocol,
            configuration_namespace="pajin.crypto",
            configuration_id="production-policy",
            declaration_sha256="4" * 64,
        )
    return typed_cryptography_protocol_key_artifact_surface(locator=locator)


def _artifact_digest(surface: CryptographyProtocolKeyArtifactSurface) -> str:
    locator = surface.locator
    if isinstance(locator, CryptographicCiphertextSurfaceLocator):
        return locator.artifact_sha256
    if isinstance(
        locator,
        (
            CryptographicProtocolSurfaceLocator,
            CryptographicKeyUsageSurfaceLocator,
            CryptographicConfigurationSurfaceLocator,
        ),
    ):
        return locator.declaration_sha256
    raise AssertionError("unsupported Cryptographic Surface locator")


@cache
def _custody(
    surface: CryptographyProtocolKeyArtifactSurface,
    *,
    artifact_bytes: int = 4_096,
) -> CryptographicAnalysisArtifactCustodyBinding:
    return bind_cryptographic_analysis_artifact_custody(
        surface=surface,
        authorization_digest=AUTHORIZATION_DIGEST,
        artifact_bytes=artifact_bytes,
    )


@cache
def _sandbox(
    surface: CryptographyProtocolKeyArtifactSurface,
    *,
    max_artifact_bytes: int = 65_536,
    analyzer_executable_sha256: str = ANALYZER_DIGEST,
    sandbox_image_sha256: str = SANDBOX_IMAGE_DIGEST,
) -> CryptographicMisuseAnalysisSandboxBinding:
    return bind_cryptographic_misuse_analysis_sandbox(
        surface=surface,
        analyzer_executable_sha256=analyzer_executable_sha256,
        sandbox_image_sha256=sandbox_image_sha256,
        max_artifact_bytes=max_artifact_bytes,
        max_output_bytes=131_072,
        max_runtime_seconds=30,
        max_memory_mib=256,
        max_process_count=4,
    )


@cache
def _adapter(
    surface: CryptographyProtocolKeyArtifactSurface,
    *,
    artifact_bytes: int = 4_096,
    max_artifact_bytes: int = 65_536,
    analyzer_executable_sha256: str = ANALYZER_DIGEST,
    sandbox_image_sha256: str = SANDBOX_IMAGE_DIGEST,
) -> BoundedCryptographicMisuseAnalyzerAdapter:
    return BoundedCryptographicMisuseAnalyzerAdapter(
        _custody(surface, artifact_bytes=artifact_bytes),
        _sandbox(
            surface,
            max_artifact_bytes=max_artifact_bytes,
            analyzer_executable_sha256=analyzer_executable_sha256,
            sandbox_image_sha256=sandbox_image_sha256,
        ),
    )


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    surface: CryptographyProtocolKeyArtifactSurface,
    include_surface: bool = True,
    allow_get: bool = True,
    allow_private: bool = False,
    deny: list[str] | None = None,
    wildcard_only: bool = False,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    if wildcard_only:
        allow = [f"{CRYPTOGRAPHIC_SURFACE_SCOPE_ORIGIN}/surfaces/*"]
    elif include_surface:
        allow = [cryptographic_surface_scope_target(surface)]
    else:
        allow = ["https://unrelated.example.test/"]
    payload["spec"]["scope"] = {"allow": allow, "deny": deny or []}
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
    surface: CryptographyProtocolKeyArtifactSurface | None = None,
) -> CryptographicMisuseAnalysisPreparation:
    selected = surface or _surface()
    activation, release = _activation()
    return prepare_cryptographic_misuse_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=selected),
        surface=selected,
        operation=_OPERATION_BY_CLASS[selected.surface_class],
        analyzer=_adapter(selected),
        request_id="tool_cryptographic_misuse_analysis_prepare",
        agent_id="agent:cryptographic-misuse-analysis",
    )


def test_capability_binding_pins_crypto_surface_rule_set_and_worker_boundary() -> None:
    definition = registered_cryptographic_misuse_analysis_capability_definition()
    binding = registered_cryptographic_misuse_analysis_binding()
    tools = ToolRegistry()
    tools.register(CryptographicMisuseAnalysisTool())
    bundle = cryptographic_misuse_analysis_capability_bundle(tools)
    crypto_worker = next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    )

    assert definition.capability_id == CRYPTOGRAPHIC_MISUSE_ANALYSIS_CAPABILITY_ID
    assert definition.supported_surface_types == (
        "cryptography-ciphertext",
        "cryptography-configuration",
        "cryptography-key-usage",
        "cryptography-protocol",
    )
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is False
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert binding.capability == bundle.capability()
    assert binding.worker_profile == crypto_worker.reference()
    assert binding.rule_set == registered_cryptographic_misuse_rule_set()
    assert len(binding.supported_locators) == 4
    assert all(
        binding.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _BINDING_FALSE_MARKERS
    )

    classification = registered_cryptographic_misuse_analysis_capability_domain_classification()
    assert classification.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    assert classification.global_domain_inventory_changed is False
    assert classification.ctf_capability_reused is False
    assert (
        resolve_cryptographic_misuse_analysis_capability_domain_classification(
            classification.reference()
        )
        == classification
    )
    assert resolve_cryptographic_misuse_analysis_binding(binding.reference()) == binding


def test_code_owned_rule_set_is_exact_bounded_and_non_executable() -> None:
    rule_set = registered_cryptographic_misuse_rule_set()
    payload = rule_set.model_dump(mode="json", by_alias=True)

    assert rule_set.rule_set_id == "pajin.cryptography.misuse-rules.baseline"
    assert rule_set.rule_set_version == "1.0.0"
    assert rule_set.signal_vocabulary == tuple(
        sorted(CryptographicMisuseSignalKind, key=lambda item: item.value)
    )
    assert tuple(item.surface_class for item in rule_set.surface_analysis_mapping) == tuple(
        sorted(CryptographySurfaceClass, key=lambda item: item.value)
    )
    assert all(
        isinstance(item, CryptographicSurfaceAnalysisMapping)
        for item in rule_set.surface_analysis_mapping
    )
    for item in rule_set.surface_analysis_mapping:
        assert item.locator_kind == _LOCATOR_KIND_BY_CLASS[item.surface_class]
        assert item.input_kind is _INPUT_KIND_BY_CLASS[item.surface_class]
        assert item.digest_source is _DIGEST_SOURCE_BY_CLASS[item.surface_class]
        assert item.operation is _OPERATION_BY_CLASS[item.surface_class]
        assert item.analyzer is _ANALYZER_BY_CLASS[item.surface_class]
    assert resolve_registered_cryptographic_misuse_rule_set(rule_set.reference()) == rule_set
    assert rule_set.analyzer_runtime_available is False
    assert rule_set.misuse_confirmed is False
    assert rule_set.finding_authority is False
    assert rule_set.execution_authorized is False

    mapping_material: list[dict[str, object]] = [
        item.model_dump(mode="json", by_alias=True) for item in rule_set.surface_analysis_mapping
    ]
    digest_material: dict[str, object] = {
        "ruleSetId": rule_set.rule_set_id,
        "ruleSetVersion": rule_set.rule_set_version,
        "signalVocabulary": [item.value for item in rule_set.signal_vocabulary],
        "surfaceAnalysisMapping": mapping_material,
    }
    assert rule_set.rule_set_digest == capability_definition_digest(
        "pajin.capability.cryptographic-misuse-rule-set/v1",
        digest_material,
    )
    changed_mapping = deepcopy(mapping_material)
    changed_mapping[0]["operation"] = (
        CryptographicMisuseAnalysisOperation.PROTOCOL_DECLARATION.value
    )
    changed_material = {**digest_material, "surfaceAnalysisMapping": changed_mapping}
    assert (
        capability_definition_digest(
            "pajin.capability.cryptographic-misuse-rule-set/v1",
            changed_material,
        )
        != rule_set.rule_set_digest
    )

    reversed_payload = deepcopy(payload)
    reversed_payload["signalVocabulary"] = list(reversed(payload["signalVocabulary"]))
    reversed_payload["ruleSetDigest"] = ""
    with pytest.raises(ValidationError, match="semantics differ"):
        RegisteredCryptographicMisuseRuleSet.model_validate(reversed_payload)

    mapping_payload = deepcopy(payload)
    mapping_payload["surfaceAnalysisMapping"][0]["inputKind"] = (
        CryptographicAnalysisInputKind.SANITIZED_PROTOCOL_DECLARATION.value
    )
    mapping_payload["ruleSetDigest"] = ""
    with pytest.raises(ValidationError, match="mapping differs"):
        RegisteredCryptographicMisuseRuleSet.model_validate(mapping_payload)

    reordered_mapping = deepcopy(payload)
    reordered_mapping["surfaceAnalysisMapping"] = list(
        reversed(reordered_mapping["surfaceAnalysisMapping"])
    )
    reordered_mapping["ruleSetDigest"] = ""
    with pytest.raises(ValidationError, match="semantics differ"):
        RegisteredCryptographicMisuseRuleSet.model_validate(reordered_mapping)

    for alias in (
        "callerRuleSelectionAllowed",
        "pluginLoadingAllowed",
        "analyzerRuntimeAvailable",
        "misuseConfirmed",
        "findingAuthority",
        "executionAuthorized",
    ):
        changed = deepcopy(payload)
        changed[alias] = True
        with pytest.raises(ValidationError):
            RegisteredCryptographicMisuseRuleSet.model_validate(changed)

        changed[alias] = 0
        with pytest.raises(ValidationError, match="must be booleans"):
            RegisteredCryptographicMisuseRuleSet.model_validate(changed)

    changed = deepcopy(payload)
    changed["ruleSetOnly"] = False
    with pytest.raises(ValidationError):
        RegisteredCryptographicMisuseRuleSet.model_validate(changed)

    changed["ruleSetOnly"] = 1
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredCryptographicMisuseRuleSet.model_validate(changed)

    reference = rule_set.reference()
    reference_payload = reference.model_dump(mode="json", by_alias=True)
    reference_payload["ruleSetDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="reference differs"):
        type(reference).model_validate(reference_payload)
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="unmodeled"):
        resolve_registered_cryptographic_misuse_rule_set(
            reference.model_copy(update={"plugin": "attacker-rule"})
        )


def test_public_registered_values_are_isolated_from_process_local_mutation() -> None:
    rule_set = registered_cryptographic_misuse_rule_set()
    direct_rule_set = RegisteredCryptographicMisuseRuleSet()
    other_direct_rule_set = RegisteredCryptographicMisuseRuleSet()
    binding = registered_cryptographic_misuse_analysis_binding()
    classification = registered_cryptographic_misuse_analysis_capability_domain_classification()
    definition = registered_cryptographic_misuse_analysis_capability_definition()

    original_analyzer = rule_set.surface_analysis_mapping[0].analyzer
    replacement_analyzer = next(
        item for item in CryptographicMisuseAnalyzer if item is not original_analyzer
    )
    object.__setattr__(rule_set, "execution_authorized", True)
    object.__setattr__(rule_set.surface_analysis_mapping[0], "analyzer", replacement_analyzer)
    object.__setattr__(binding, "execution_authorized", True)
    object.__setattr__(classification, "execution_authorized", True)
    object.__setattr__(definition, "network_access", True)

    fresh_rule_set = registered_cryptographic_misuse_rule_set()
    assert (
        direct_rule_set.surface_analysis_mapping[0]
        is not (other_direct_rule_set.surface_analysis_mapping[0])
    )
    assert fresh_rule_set.execution_authorized is False
    assert fresh_rule_set.surface_analysis_mapping[0].analyzer is original_analyzer
    assert registered_cryptographic_misuse_analysis_binding().execution_authorized is False
    assert (
        registered_cryptographic_misuse_analysis_capability_domain_classification().execution_authorized
        is False
    )
    assert registered_cryptographic_misuse_analysis_capability_definition().network_access is False


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("toolId", "attacker.substituted-cryptographic-tool"),
        ("toolVersion", "9.9.9"),
        ("toolDigest", "0" * 64),
        ("riskTier", 0),
    ),
)
def test_activation_rejects_action_metadata_substitution(
    field: str,
    replacement: str | int,
) -> None:
    activation, _ = _activation()
    original_set = activation.activation_set
    payload = original_set.model_dump(mode="json", by_alias=True)
    expected_action = original_set.binding.action_capability
    assert activation.action_registry().resolve(expected_action.reference()) == expected_action

    payload["binding"]["actionCapability"][field] = replacement
    payload["binding"]["actionCapability"]["capabilityDigest"] = ""
    tampered_action = type(expected_action).model_validate(payload["binding"]["actionCapability"])
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


@pytest.mark.parametrize("surface_class", tuple(CryptographySurfaceClass))
def test_all_crypto_surfaces_bind_class_owned_input_operation_and_analyzer(
    surface_class: CryptographySurfaceClass,
) -> None:
    surface = _surface(surface_class)
    custody = _custody(surface)
    sandbox = _sandbox(surface)
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface_class],
    )

    assert custody.surface == surface
    assert custody.input_kind is _INPUT_KIND_BY_CLASS[surface_class]
    assert custody.artifact_sha256 == _artifact_digest(surface)
    assert custody.custody_authority_id == CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_CUSTODY_AUTHORITY_ID
    assert custody.custody_object_id == (
        f"cryptographic-analysis-artifact_{custody.artifact_sha256}"
    )
    assert custody.authorization_id == (
        f"cryptographic-analysis-authorization_{AUTHORIZATION_DIGEST}"
    )
    assert custody.artifact_bytes == 4_096
    assert request.surface == surface
    assert request.input_kind is _INPUT_KIND_BY_CLASS[surface_class]
    assert request.operation is _OPERATION_BY_CLASS[surface_class]
    assert request.analyzer is _ANALYZER_BY_CLASS[surface_class]
    assert request.rule_set == registered_cryptographic_misuse_rule_set().reference()
    assert request.target == cryptographic_surface_scope_target(surface)
    assert request.method == "GET"
    assert request.output_schema == CRYPTOGRAPHIC_MISUSE_ANALYSIS_OUTPUT_SCHEMA
    assert sandbox.surface == surface
    assert sandbox.operation is request.operation
    assert sandbox.analyzer is request.analyzer
    assert sandbox.artifact_mount_target == CRYPTOGRAPHIC_ANALYSIS_ARTIFACT_MOUNT_TARGET
    assert all(
        request.budget.model_dump(mode="json", by_alias=True)[field] == 0
        for field in _BUDGET_ZERO_FIELDS
    )
    assert all(
        custody.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _CUSTODY_FALSE_MARKERS
    )
    assert all(
        sandbox.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _SANDBOX_FALSE_MARKERS
    )
    assert all(
        request.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _REQUEST_FALSE_MARKERS
    )
    assert (
        CryptographicAnalysisArtifactCustodyBinding.model_validate(
            custody.model_dump(mode="json", by_alias=True)
        )
        == custody
    )
    assert (
        CryptographicMisuseAnalysisSandboxBinding.model_validate(
            sandbox.model_dump(mode="json", by_alias=True)
        )
        == sandbox
    )
    assert (
        CryptographicMisuseAnalysisRequest.model_validate(
            request.model_dump(mode="json", by_alias=True)
        )
        == request
    )


def test_sandbox_pins_exact_crypto_profile_and_offline_read_only_boundaries() -> None:
    sandbox = _sandbox(_surface(CryptographySurfaceClass.CIPHERTEXT))
    profile = resolve_registered_domain_worker_boundary_profile(sandbox.worker_profile)

    assert profile.domain_classification.domain is SecurityDomain.CRYPTOGRAPHY
    assert profile.network_boundary is WorkerNetworkBoundary.DISABLED_BY_DEFAULT
    assert profile.filesystem_boundary is WorkerFilesystemBoundary.READ_ONLY_ARTIFACT
    assert profile.credential_boundary is WorkerCredentialBoundary.NONE
    assert profile.runtime_boundary is WorkerRuntimeBoundary.OFFLINE_SANDBOX
    assert profile.required_identity_dimensions == ("analyzer", "artifact-digest")
    assert profile.required_budget_dimensions == ("artifact-bytes", "runtime")
    assert sandbox.network_disabled_required is True
    assert sandbox.dns_disabled_required is True
    assert sandbox.read_only_root_filesystem_required is True
    assert sandbox.read_only_artifact_mount_required is True
    assert sandbox.artifact_mount_noexec_required is True
    assert sandbox.non_root_runtime_required is True
    assert sandbox.deployment_id == CRYPTOGRAPHIC_MISUSE_ANALYSIS_DEPLOYMENT_ID
    assert sandbox.run_as_identity == CRYPTOGRAPHIC_MISUSE_ANALYSIS_RUN_AS_IDENTITY
    builder_parameters = signature(bind_cryptographic_misuse_analysis_sandbox).parameters
    assert "deployment_id" not in builder_parameters
    assert "run_as_identity" not in builder_parameters


def test_signed_preparation_binds_scope_custody_sandbox_and_stops_before_dispatch(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(CryptographySurfaceClass.CONFIGURATION)
    preparation = _prepare(sample_campaign, surface=surface)
    request = preparation.prepared_action.request

    assert preparation.state == "prepared-not-authorized"
    assert preparation.surface == surface
    assert (
        preparation.input_kind is CryptographicAnalysisInputKind.SANITIZED_CONFIGURATION_DECLARATION
    )
    assert preparation.matched_surface_allow_rule == cryptographic_surface_scope_target(surface)
    assert request.tool_id == CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID
    assert request.target == preparation.analysis_request.target
    assert request.method == "GET"
    assert request.arguments == preparation.analysis_request.model_dump(
        mode="json",
        by_alias=True,
    )
    assert all(
        preparation.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _PREPARATION_FALSE_MARKERS
    )


@pytest.mark.parametrize(
    ("include_surface", "allow_get", "wildcard_only"),
    (
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ),
)
def test_preparation_requires_one_exact_surface_allow_and_get(
    sample_campaign: CampaignManifest,
    include_surface: bool,
    allow_get: bool,
    wildcard_only: bool,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
        prepare_cryptographic_misuse_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(
                sample_campaign,
                surface=surface,
                include_surface=include_surface,
                allow_get=allow_get,
                wildcard_only=wildcard_only,
            ),
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            analyzer=_adapter(surface),
            request_id="tool_crypto_scope_rejected",
            agent_id="agent:cryptographic-misuse-analysis",
        )


def test_deny_overrides_scope_and_private_flag_does_not_open_live_channels(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(CryptographySurfaceClass.KEY_USAGE)
    target = cryptographic_surface_scope_target(surface)
    activation, release = _activation()

    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="deny"):
        prepare_cryptographic_misuse_analysis(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign, surface=surface, deny=[target]),
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            analyzer=_adapter(surface),
            request_id="tool_crypto_scope_denied",
            agent_id="agent:cryptographic-misuse-analysis",
        )

    preparation = prepare_cryptographic_misuse_analysis(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign, surface=surface, allow_private=True),
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
        analyzer=_adapter(surface),
        request_id="tool_crypto_private_scope",
        agent_id="agent:cryptographic-misuse-analysis",
    )
    budget = preparation.analysis_request.budget
    assert preparation.campaign_scope.allow_private_networks is True
    assert budget.network_requests == 0
    assert budget.dns_queries == 0
    assert preparation.analysis_request.network_access_authorized is False


def test_surface_operation_custody_and_sandbox_substitution_fail_closed() -> None:
    protocol = _surface(CryptographySurfaceClass.PROTOCOL)
    key_usage = _surface(CryptographySurfaceClass.KEY_USAGE)

    with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
        BoundedCryptographicMisuseAnalyzerAdapter(_custody(protocol), _sandbox(key_usage))

    adapter = _adapter(protocol)
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="operation differs"):
        adapter.prepare_request(
            surface=protocol,
            operation=CryptographicMisuseAnalysisOperation.CIPHERTEXT_STRUCTURE,
        )
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
        adapter.prepare_request(
            surface=key_usage,
            operation=_OPERATION_BY_CLASS[key_usage.surface_class],
        )
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="byte ceiling"):
        _adapter(protocol, artifact_bytes=65_537).prepare_request(
            surface=protocol,
            operation=_OPERATION_BY_CLASS[protocol.surface_class],
        )


@pytest.mark.parametrize(
    "surface_class",
    (
        CryptographySurfaceClass.KEY_USAGE,
        CryptographySurfaceClass.CIPHERTEXT,
        CryptographySurfaceClass.CONFIGURATION,
    ),
)
def test_same_child_digest_with_different_protocol_parent_fails_closed(
    surface_class: CryptographySurfaceClass,
) -> None:
    first_parent = cryptographic_protocol_surface_locator(
        protocol_namespace="ietf",
        protocol_id="tls-1.3",
        declaration_sha256="a" * 64,
    )
    second_parent = cryptographic_protocol_surface_locator(
        protocol_namespace="ietf",
        protocol_id="tls-1.2",
        declaration_sha256="a" * 64,
    )
    first_locator: (
        CryptographicKeyUsageSurfaceLocator
        | CryptographicCiphertextSurfaceLocator
        | CryptographicConfigurationSurfaceLocator
    )
    second_locator: (
        CryptographicKeyUsageSurfaceLocator
        | CryptographicCiphertextSurfaceLocator
        | CryptographicConfigurationSurfaceLocator
    )
    if surface_class is CryptographySurfaceClass.KEY_USAGE:
        first_locator = cryptographic_key_usage_surface_locator(
            parent=first_parent,
            usage_kind=CryptographicKeyUsageKind.DECRYPTION,
            declaration_sha256="b" * 64,
        )
        second_locator = cryptographic_key_usage_surface_locator(
            parent=second_parent,
            usage_kind=CryptographicKeyUsageKind.DECRYPTION,
            declaration_sha256="b" * 64,
        )
    elif surface_class is CryptographySurfaceClass.CIPHERTEXT:
        first_locator = cryptographic_ciphertext_surface_locator(
            parent=first_parent,
            artifact_sha256="b" * 64,
        )
        second_locator = cryptographic_ciphertext_surface_locator(
            parent=second_parent,
            artifact_sha256="b" * 64,
        )
    else:
        first_locator = cryptographic_configuration_surface_locator(
            parent=first_parent,
            configuration_namespace="pajin.crypto",
            configuration_id="policy",
            declaration_sha256="b" * 64,
        )
        second_locator = cryptographic_configuration_surface_locator(
            parent=second_parent,
            configuration_namespace="pajin.crypto",
            configuration_id="policy",
            declaration_sha256="b" * 64,
        )
    first = typed_cryptography_protocol_key_artifact_surface(locator=first_locator)
    second = typed_cryptography_protocol_key_artifact_surface(locator=second_locator)

    assert first.surface_digest != second.surface_digest
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
        BoundedCryptographicMisuseAnalyzerAdapter(_custody(first), _sandbox(second))

    first_request = _adapter(first).prepare_request(
        surface=first,
        operation=_OPERATION_BY_CLASS[surface_class],
    )
    payload = first_request.model_dump(mode="json", by_alias=True)
    payload["surface"] = second.model_dump(mode="json", by_alias=True)
    payload["target"] = cryptographic_surface_scope_target(second)
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("deploymentId", "kms:production-signing-key"),
        ("deploymentId", "sk_live_supersecret"),
        ("runAsIdentity", "root"),
        ("runAsIdentity", "root_service"),
        ("runAsIdentity", "service_root"),
        ("runAsIdentity", "uid:0"),
        ("runAsIdentity", "0:1000"),
        ("runAsIdentity", "uid:0:gid:1000"),
        ("runAsIdentity", "kms:production-signing-key"),
        ("runAsIdentity", "sk_live_supersecret"),
    ),
)
def test_sandbox_rejects_caller_controlled_identity_and_secret_smuggling(
    field: str,
    value: str,
) -> None:
    sandbox = _sandbox(_surface())
    binding_payload = sandbox.model_dump(mode="json", by_alias=True)
    binding_payload[field] = value
    binding_payload["sandboxBindingDigest"] = ""
    binding_payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisSandboxBinding.model_validate(binding_payload)

    reference_payload = sandbox.reference().model_dump(mode="json", by_alias=True)
    reference_payload[field] = value
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisSandboxRef.model_validate(reference_payload)


@pytest.mark.parametrize("artifact_bytes", (True, 0, 536_870_913))
def test_custody_byte_ceiling_and_exact_integer_type_fail_closed(
    artifact_bytes: object,
) -> None:
    payload = _custody(_surface()).model_dump(mode="json", by_alias=True)
    payload["artifactBytes"] = artifact_bytes
    payload["custodyBindingDigest"] = ""
    payload["custodyBindingId"] = ""
    with pytest.raises(ValidationError):
        CryptographicAnalysisArtifactCustodyBinding.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("maxArtifactBytes", True),
        ("maxArtifactBytes", 536_870_913),
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
def test_sandbox_resource_ceilings_and_exact_integer_types_fail_closed(
    field: str,
    value: object,
) -> None:
    payload = _sandbox(_surface()).model_dump(mode="json", by_alias=True)
    payload[field] = value
    payload["sandboxBindingDigest"] = ""
    payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisSandboxBinding.model_validate(payload)


@pytest.mark.parametrize("field", _BUDGET_ZERO_FIELDS)
def test_request_cannot_expand_live_secret_or_mutating_budget(field: str) -> None:
    surface = _surface()
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] = 1
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisRequest.model_validate(payload)

    payload["budget"][field] = True
    with pytest.raises(ValidationError, match="must be integers"):
        CryptographicMisuseAnalysisRequest.model_validate(payload)


def test_request_rejects_authority_escalation_and_boolean_coercion() -> None:
    surface = _surface()
    original = (
        _adapter(surface)
        .prepare_request(
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
        )
        .model_dump(mode="json", by_alias=True)
    )
    for alias in _REQUEST_FALSE_MARKERS:
        payload = deepcopy(original)
        payload[alias] = True
        with pytest.raises(ValidationError):
            CryptographicMisuseAnalysisRequest.model_validate(payload)

        payload[alias] = 0
        with pytest.raises(ValidationError, match="must be booleans"):
            CryptographicMisuseAnalysisRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "increment"),
    (
        ("requestCount", 1),
        ("artifactBytes", 1),
        ("maxOutputBytes", 1_024),
        ("runtimeSeconds", 1),
        ("memoryMiB", 64),
        ("processCount", 1),
    ),
)
def test_request_cannot_drift_from_custody_or_sandbox_ceilings(
    field: str,
    increment: int,
) -> None:
    surface = _surface()
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    payload = request.model_dump(mode="json", by_alias=True)
    payload["budget"][field] += increment
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisRequest.model_validate(payload)


def test_runtime_executor_normalizer_oracle_replay_and_cleanup_remain_unavailable(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    tool = CryptographicMisuseAnalysisTool()
    activation = _activation()[0]
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    normalizer = activation.authority(CapabilityAuthorityRole.RESULT_NORMALIZER)
    oracle = activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE)
    replay = activation.authority(CapabilityAuthorityRole.REPLAY_STRATEGY)
    cleanup = activation.authority(CapabilityAuthorityRole.CLEANUP_HANDLER)
    result = ToolResult(
        request_id=preparation.prepared_action.request.request_id,
        tool_id=CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID,
        success=True,
        started_at=NOW,
        finished_at=NOW,
    )
    worker_result = WorkerResult(
        execution_id="cryptographic-misuse-analysis-execution",
        backend="unavailable-cryptographic-misuse-analyzer",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=NOW,
        finished_at=NOW,
    )

    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="does not materialize"):
        tool.prepare(preparation.prepared_action.request)
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="does not materialize"):
        executor.prepare(preparation.prepared_action.request)
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="no sandbox result"):
        tool.interpret(preparation.prepared_action.request, worker_result)
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="no sandbox result"):
        normalizer.normalize(preparation.prepared_action.request, worker_result)
    assert (
        oracle.evaluate(preparation.prepared_action.request, result)
        is CapabilityOracleDecision.INCONCLUSIVE
    )
    assert replay.plan_replay(preparation.prepared_action.request, result) is None
    assert cleanup.plan_cleanup(preparation.prepared_action.request, result) is None


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_cryptographic_misuse_analysis_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        CryptographicMisuseAnalysisBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _CUSTODY_FALSE_MARKERS)
def test_custody_rejects_artifact_or_authority_escalation(alias: str) -> None:
    payload = _custody(_surface()).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["custodyBindingDigest"] = ""
    payload["custodyBindingId"] = ""
    with pytest.raises(ValidationError):
        CryptographicAnalysisArtifactCustodyBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _SANDBOX_FALSE_MARKERS)
def test_sandbox_rejects_runtime_authority_escalation(alias: str) -> None:
    payload = _sandbox(_surface()).model_dump(mode="json", by_alias=True)
    payload[alias] = True
    payload["sandboxBindingDigest"] = ""
    payload["sandboxBindingId"] = ""
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisSandboxBinding.model_validate(payload)


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
        CryptographicMisuseAnalysisPreparation.model_validate(payload)


def test_preparation_rejects_custody_sandbox_scope_release_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("artifactCustody", "authorizationDigest", "0" * 64),
        ("artifactCustody", "artifactSHA256", "0" * 64),
        ("sandbox", "analyzerExecutableSHA256", "0" * 64),
        ("sandbox", "sandboxImageSHA256", "0" * 64),
        ("sandbox", "ruleSet", {"ruleSetId": "attacker-rule"}),
        ("campaignScope", "campaignDigest", "0" * 64),
        (
            "analysisRequest",
            "target",
            cryptographic_surface_scope_target(_surface(CryptographySurfaceClass.CIPHERTEXT)),
        ),
        ("analysisRequest", "outputSchema", "attacker.output.v1"),
        ("preparedAction", "requestDigest", "0" * 64),
        ("preparedAction", "normalizedParametersDigest", "0" * 64),
        (None, "inputKind", CryptographicAnalysisInputKind.CIPHERTEXT_ARTIFACT.value),
        (None, "operation", CryptographicMisuseAnalysisOperation.CIPHERTEXT_STRUCTURE.value),
        (None, "preparationDigest", "0" * 64),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            CryptographicMisuseAnalysisPreparation.model_validate(payload)


def test_stale_release_and_tool_request_substitution_fail_closed(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface()
    activation, release = _activation()
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
        prepare_cryptographic_misuse_analysis(
            activation=activation,
            release=release.model_copy(update={"release_digest": "0" * 64}),
            campaign=_campaign(sample_campaign, surface=surface),
            surface=surface,
            operation=_OPERATION_BY_CLASS[surface.surface_class],
            analyzer=_adapter(surface),
            request_id="tool_crypto_stale_release",
            agent_id="agent:cryptographic-misuse-analysis",
        )

    request = _prepare(sample_campaign).prepared_action.request
    tool = CryptographicMisuseAnalysisTool()
    for changed in (
        request.model_copy(update={"target": "https://other.example.test/v1/analyze"}),
        request.model_copy(update={"method": "POST"}),
        request.model_copy(update={"tool_id": CTF_CRYPTO_XOR_TOOL_ID}),
    ):
        with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
            tool.prepare(changed)


def test_models_reject_keys_secrets_paths_commands_plugins_and_ctf_fields() -> None:
    surface = _surface(CryptographySurfaceClass.CIPHERTEXT)
    custody_payload = _custody(surface).model_dump(mode="json", by_alias=True)
    custody_injections: tuple[tuple[str, object], ...] = (
        ("artifactPath", r"C:\artifacts\ciphertext.bin"),
        ("rawKey", "secret-key"),
        ("keyAlias", "production-key"),
        ("kmsKeyId", "kms://production-key"),
        ("pkcs11URI", "pkcs11:token=production"),
        ("ciphertext", "base64-data"),
        ("plaintext", "secret-plaintext"),
    )
    for field, value in custody_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CryptographicAnalysisArtifactCustodyBinding.model_validate(
                {**custody_payload, field: value}
            )

    sandbox_payload = _sandbox(surface).model_dump(mode="json", by_alias=True)
    sandbox_injections: tuple[tuple[str, object], ...] = (
        ("endpoint", "https://kms.example.test"),
        ("credential", {"token": "secret"}),
        ("command", ["openssl", "enc"]),
        ("plugin", "custom-crypto-rule"),
        ("oracle", {"challengeId": "challenge-1"}),
    )
    for field, value in sandbox_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CryptographicMisuseAnalysisSandboxBinding.model_validate(
                {**sandbox_payload, field: value}
            )

    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    request_payload = request.model_dump(mode="json", by_alias=True)
    request_injections: tuple[tuple[str, object], ...] = (
        ("jwk", {"kty": "oct", "k": "secret"}),
        ("certificate", "certificate-data"),
        ("password", "secret"),
        ("pin", "1234"),
        ("seed", "secret-seed"),
        ("nonce", "00"),
        ("iv", "00"),
        ("salt", "00"),
        ("tag", "00"),
        ("aad", "00"),
        ("ciphertextHex", "00"),
        ("challengeId", "ctf-challenge"),
        ("recoveredKey", "secret-key"),
    )
    for field, value in request_injections:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CryptographicMisuseAnalysisRequest.model_validate({**request_payload, field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("custodyAuthorityId", "kms:production"),
        ("custodyAuthorityId", "pkcs11:production"),
        ("custodyObjectId", "alias-production-signing-key"),
        ("custodyObjectId", f"cryptographic-analysis-artifact_{'0' * 64}"),
        ("authorizationId", "eyJhbGciOiJIUzI1NiJ9.payload.signature"),
        ("authorizationId", f"cryptographic-analysis-authorization_{'0' * 64}"),
    ),
)
def test_custody_identifiers_cannot_smuggle_key_or_credential_references(
    field: str,
    value: str,
) -> None:
    payload = _custody(_surface()).model_dump(mode="json", by_alias=True)
    payload[field] = value
    payload["custodyBindingId"] = ""
    payload["custodyBindingDigest"] = ""
    with pytest.raises(ValidationError):
        CryptographicAnalysisArtifactCustodyBinding.model_validate(payload)


def test_forged_model_copy_state_fails_at_public_boundaries(
    sample_campaign: CampaignManifest,
) -> None:
    surface = _surface(CryptographySurfaceClass.KEY_USAGE)
    forged_surface = surface.model_copy(update={"rawKey": "secret"})
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="unmodeled"):
        bind_cryptographic_analysis_artifact_custody(
            surface=forged_surface,
            authorization_digest=AUTHORIZATION_DIGEST,
            artifact_bytes=4_096,
        )

    custody = _custody(surface)
    forged_custody = custody.model_copy(update={"bearerToken": "secret"})
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="unmodeled"):
        BoundedCryptographicMisuseAnalyzerAdapter(forged_custody, _sandbox(surface))

    binding_ref = registered_cryptographic_misuse_analysis_binding().reference()
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="unmodeled"):
        resolve_cryptographic_misuse_analysis_binding(
            binding_ref.model_copy(update={"secret": "token"})
        )

    classification = registered_cryptographic_misuse_analysis_capability_domain_classification()
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="unmodeled"):
        resolve_cryptographic_misuse_analysis_capability_domain_classification(
            classification.reference().model_copy(update={"keyId": "secret-key"})
        )

    request = _prepare(sample_campaign).prepared_action.request
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError, match="unmodeled"):
        CryptographicMisuseAnalysisTool().prepare(
            request.model_copy(update={"credential": "secret"})
        )


def test_reference_digests_and_exact_crypto_profile_reject_drift() -> None:
    surface = _surface(CryptographySurfaceClass.CIPHERTEXT)
    request = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )

    custody_ref = request.custody.model_dump(mode="json", by_alias=True)
    custody_ref["custodyObjectId"] = "object-mutated"
    with pytest.raises(ValidationError):
        CryptographicAnalysisArtifactCustodyRef.model_validate(custody_ref)

    sandbox_ref = request.sandbox.model_dump(mode="json", by_alias=True)
    sandbox_ref["maxArtifactBytes"] += 1
    with pytest.raises(ValidationError):
        CryptographicMisuseAnalysisSandboxRef.model_validate(sandbox_ref)

    application_profile = next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.APPLICATION
    )
    sandbox_payload = _sandbox(surface).model_dump(mode="json", by_alias=True)
    sandbox_payload["workerProfile"] = application_profile.reference().model_dump(
        mode="json",
        by_alias=True,
    )
    sandbox_payload["sandboxBindingId"] = ""
    sandbox_payload["sandboxBindingDigest"] = ""
    with pytest.raises(ValidationError, match="code authority"):
        CryptographicMisuseAnalysisSandboxBinding.model_validate(sandbox_payload)


def test_capability_materializer_rejects_mutated_reference_summary() -> None:
    surface = _surface(CryptographySurfaceClass.CONFIGURATION)
    analysis = _adapter(surface).prepare_request(
        surface=surface,
        operation=_OPERATION_BY_CLASS[surface.surface_class],
    )
    parameters = analysis.model_dump(mode="json", by_alias=True)
    parameters["custody"]["authorizationDigest"] = "0" * 64
    activation, release = _activation()
    request = ToolRequest(
        request_id="tool_crypto_mutated_reference",
        agent_id="agent:cryptographic-misuse-analysis",
        tool_id=CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID,
        target=analysis.target,
        method="GET",
        arguments={},
    )
    with pytest.raises(CryptographicMisuseAnalysisCapabilityError):
        activation.prepare_action(
            release=release,
            request=request,
            parameters=parameters,
        )


def test_ctf_xor_runtime_is_not_reused_and_runtime_authority_fields_are_absent() -> None:
    tool = CryptographicMisuseAnalysisTool()
    context = tool.stable_execution_context()
    forbidden = {
        "key",
        "raw_key",
        "key_alias",
        "kms_endpoint",
        "pkcs11_uri",
        "credential",
        "token",
        "artifact_path",
        "command",
        "plugin",
        "oracle",
        "challenge_id",
        "scenario_id",
        "recovered_key",
        "plaintext",
        "worker_job",
        "permit",
        "observation",
        "evidence",
        "finding",
    }

    assert CRYPTOGRAPHIC_MISUSE_ANALYSIS_TOOL_ID != CTF_CRYPTO_XOR_TOOL_ID
    assert context["ruleSet"] == registered_cryptographic_misuse_rule_set().reference().model_dump(
        mode="json",
        by_alias=True,
    )
    assert context["keyMaterialRuntimeAvailable"] is False
    assert context["cryptographicOperationRuntimeAvailable"] is False
    assert context["oracleRuntimeAvailable"] is False
    assert context["workerJobMaterializationAvailable"] is False
    assert forbidden.isdisjoint(CryptographicMisuseAnalysisBudget.model_fields)
    assert forbidden.isdisjoint(CryptographicMisuseAnalysisRequest.model_fields)
    assert forbidden.isdisjoint(CryptographicMisuseAnalysisPreparation.model_fields)
