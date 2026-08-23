"""DOMAIN-004 deployment bindings for non-authoritative Worker boundary profiles."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.domain_projection import (
    CapabilityDomainClassificationRef,
    CapabilityDomainProjectionError,
    RegisteredCapabilityDomainClassification,
    resolve_registered_capability_domain_classification,
)
from pajin.capabilities.existing import ExistingModeCapabilityBundle
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleRegistry,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
)
from pajin.capabilities.models import capability_definition_digest
from pajin.capabilities.pentest_recon import PentestReconCapabilityBundle
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSTrustPolicy,
)
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)

DOMAIN_WORKER_BOUNDARY_PROFILE_API_VERSION: Literal[
    "pajin.dev/domain-worker-boundary-profile/v1alpha1"
] = "pajin.dev/domain-worker-boundary-profile/v1alpha1"
DOMAIN_WORKER_BOUNDARY_PROFILE_REGISTRY_API_VERSION: Literal[
    "pajin.dev/domain-worker-boundary-profile-registry/v1alpha1"
] = "pajin.dev/domain-worker-boundary-profile-registry/v1alpha1"
DOMAIN_WORKER_DEPLOYMENT_BINDING_API_VERSION: Literal[
    "pajin.dev/domain-worker-deployment-binding/v1alpha1"
] = "pajin.dev/domain-worker-deployment-binding/v1alpha1"
DOMAIN_WORKER_DEPLOYMENT_REGISTRY_API_VERSION: Literal[
    "pajin.dev/domain-worker-deployment-registry/v1alpha1"
] = "pajin.dev/domain-worker-deployment-registry/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PROFILE_ID_PATTERN = r"^pajin\.worker-boundary\.[a-z-]+\.minimum$"
_BINDING_ID_PATTERN = r"^domain-worker-binding_[a-f0-9]{64}$"
_EXPECTED_PROFILE_COUNT = len(SecurityDomain)


class DomainWorkerBoundaryError(RuntimeError):
    """Raised when a Worker boundary profile or deployment binding differs."""


class WorkerNetworkBoundary(StrEnum):
    """Minimum network isolation required by one first-slice Worker profile."""

    DISABLED_BY_DEFAULT = "disabled-by-default"
    BOUNDED_EGRESS = "bounded-egress"
    EXACT_HOST_PROTOCOL_PORT = "exact-host-protocol-port"
    DEPLOYMENT_SCOPED = "deployment-scoped"


class WorkerFilesystemBoundary(StrEnum):
    """Minimum host or artifact filesystem boundary."""

    NO_HOST_ACCESS = "no-host-access"
    BOUNDED_HOST_READ = "bounded-host-read"
    READ_ONLY_ARTIFACT = "read-only-artifact"
    IMMUTABLE_EVIDENCE = "immutable-evidence"


class WorkerCredentialBoundary(StrEnum):
    """Minimum credential custody boundary."""

    NONE = "none"
    DEPLOYMENT_AUTHENTICATION = "deployment-authentication"
    EPHEMERAL_LEASE = "ephemeral-lease"


class WorkerRuntimeBoundary(StrEnum):
    """Minimum execution environment boundary."""

    ISOLATED_NON_ROOT = "isolated-non-root"
    AUTHENTICATED_NON_ROOT_AGENT = "authenticated-non-root-agent"
    DEVICE_BOUND = "device-bound"
    OFFLINE_SANDBOX = "offline-sandbox"
    PROVENANCE_PRESERVING_PARSER = "provenance-preserving-parser"


class DomainWorkerBoundaryProfileRef(StrictModel):
    """Exact content-addressed reference to one code-owned boundary profile."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    profile_id: str = Field(alias="profileId", pattern=_PROFILE_ID_PATTERN)
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )


class RegisteredDomainWorkerBoundaryProfile(StrictModel):
    """One minimum Worker requirement set that grants no execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/domain-worker-boundary-profile/v1alpha1"] = Field(
        default=DOMAIN_WORKER_BOUNDARY_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredDomainWorkerBoundaryProfile"] = (
        "RegisteredDomainWorkerBoundaryProfile"
    )
    profile_id: str = Field(default="", alias="profileId", max_length=200)
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    network_boundary: WorkerNetworkBoundary = Field(alias="networkBoundary")
    filesystem_boundary: WorkerFilesystemBoundary = Field(alias="filesystemBoundary")
    credential_boundary: WorkerCredentialBoundary = Field(alias="credentialBoundary")
    runtime_boundary: WorkerRuntimeBoundary = Field(alias="runtimeBoundary")
    required_identity_dimensions: tuple[_Identifier, ...] = Field(
        alias="requiredIdentityDimensions",
        min_length=1,
        max_length=16,
    )
    required_budget_dimensions: tuple[_Identifier, ...] = Field(
        alias="requiredBudgetDimensions",
        min_length=1,
        max_length=16,
    )
    protocol_privilege_review_required: bool = Field(alias="protocolPrivilegeReviewRequired")
    provenance_preservation_required: bool = Field(alias="provenancePreservationRequired")
    profile_only: Literal[True] = Field(default=True, alias="profileOnly")
    deployment_binding_required: Literal[True] = Field(
        default=True,
        alias="deploymentBindingRequired",
    )
    separate_capability_required_for_dynamic_execution: Literal[True] = Field(
        default=True,
        alias="separateCapabilityRequiredForDynamicExecution",
    )
    separate_capability_required_for_mutation: Literal[True] = Field(
        default=True,
        alias="separateCapabilityRequiredForMutation",
    )
    domain_only_selection_authorized: Literal[False] = Field(
        default=False,
        alias="domainOnlySelectionAuthorized",
    )
    tool_metadata_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolMetadataSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    filesystem_access_authorized: Literal[False] = Field(
        default=False,
        alias="filesystemAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    device_access_authorized: Literal[False] = Field(
        default=False,
        alias="deviceAccessAuthorized",
    )
    evidence_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceMutationAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "protocol_privilege_review_required",
        "provenance_preservation_required",
        "profile_only",
        "deployment_binding_required",
        "separate_capability_required_for_dynamic_execution",
        "separate_capability_required_for_mutation",
        "domain_only_selection_authorized",
        "tool_metadata_selection_authorized",
        "network_access_authorized",
        "filesystem_access_authorized",
        "credential_use_authorized",
        "device_access_authorized",
        "evidence_mutation_authorized",
        "worker_selection_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Domain Worker boundary markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_profile_identity(self) -> Self:
        spec = _profile_spec(self.domain_classification.domain)
        expected_domain = _domain_classification(spec.domain)
        if (
            self.profile_id not in {"", spec.profile_id}
            or self.domain_classification != expected_domain
            or self.network_boundary is not spec.network_boundary
            or self.filesystem_boundary is not spec.filesystem_boundary
            or self.credential_boundary is not spec.credential_boundary
            or self.runtime_boundary is not spec.runtime_boundary
            or self.required_identity_dimensions != spec.required_identity_dimensions
            or self.required_budget_dimensions != spec.required_budget_dimensions
            or self.protocol_privilege_review_required
            is not spec.protocol_privilege_review_required
            or self.provenance_preservation_required
            is not spec.provenance_preservation_required
        ):
            raise ValueError("Domain Worker boundary profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = capability_definition_digest(
            "pajin.control-plane.domain-worker-boundary-profile/v1",
            material,
        )
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("Domain Worker boundary profile digest differs")
        object.__setattr__(self, "profile_id", spec.profile_id)
        object.__setattr__(self, "profile_digest", digest)
        return self

    def reference(self) -> DomainWorkerBoundaryProfileRef:
        """Return the exact detached profile identity."""

        return DomainWorkerBoundaryProfileRef(
            profileId=self.profile_id,
            profileVersion=self.profile_version,
            profileDigest=self.profile_digest,
            domainClassification=self.domain_classification,
        )


class DomainWorkerBoundaryProfileRegistry(StrictModel):
    """Exact nine-profile catalog without runtime or Worker-selection authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/domain-worker-boundary-profile-registry/v1alpha1"
    ] = Field(
        default=DOMAIN_WORKER_BOUNDARY_PROFILE_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DomainWorkerBoundaryProfileRegistry"] = (
        "DomainWorkerBoundaryProfileRegistry"
    )
    registry_id: Literal["pajin.domain-worker-boundary-profiles.minimum"] = Field(
        default="pajin.domain-worker-boundary-profiles.minimum",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    profiles: tuple[RegisteredDomainWorkerBoundaryProfile, ...] = Field(
        min_length=_EXPECTED_PROFILE_COUNT,
        max_length=_EXPECTED_PROFILE_COUNT,
    )
    profile_count: Literal[9] = Field(default=9, alias="profileCount")
    code_owned: Literal[True] = Field(default=True, alias="codeOwned")
    profile_selection_authorized: Literal[False] = Field(
        default=False,
        alias="profileSelectionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "code_owned",
        "profile_selection_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Domain Worker profile registry markers must be booleans")
        return value

    @field_validator("profile_count", mode="before")
    @classmethod
    def require_exact_profile_count(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Domain Worker profile count must be an integer")
        return value

    @model_validator(mode="after")
    def bind_registry_identity(self) -> Self:
        if self.profiles != _registered_profiles():
            raise ValueError("Domain Worker boundary registry differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        digest = capability_definition_digest(
            "pajin.control-plane.domain-worker-boundary-profile-registry/v1",
            material,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Domain Worker boundary registry digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self


class DomainWorkerDeploymentBindingRef(StrictModel):
    """Exact reference to one deployment-owned release/Worker binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: str = Field(alias="bindingId", pattern=_BINDING_ID_PATTERN)
    binding_digest: _Sha256 = Field(alias="bindingDigest")
    deployment_id: _Identifier = Field(alias="deploymentId")


class DomainWorkerDeploymentBinding(StrictModel):
    """Verified release and mTLS identity binding that still grants no dispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/domain-worker-deployment-binding/v1alpha1"] = Field(
        default=DOMAIN_WORKER_DEPLOYMENT_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DomainWorkerDeploymentBinding"] = "DomainWorkerDeploymentBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=86)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    deployment_id: _Identifier = Field(alias="deploymentId")
    capability: CodeBackedCapabilityRef
    capability_release: CapabilityReleaseRef = Field(alias="capabilityRelease")
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability_domain_classification: CapabilityDomainClassificationRef = Field(
        alias="capabilityDomainClassification"
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    worker_mtls_policy_id: str = Field(
        alias="workerMTLSPolicyId",
        pattern=r"^worker-mtls-policy_[0-9a-f]{32}$",
    )
    worker_mtls_policy_digest: _Sha256 = Field(alias="workerMTLSPolicyDigest")
    worker_identity: WorkerCertificateBinding = Field(alias="workerIdentity")
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")
    signed_release_verified: Literal[True] = Field(default=True, alias="signedReleaseVerified")
    capability_domain_classification_verified: Literal[True] = Field(
        default=True,
        alias="capabilityDomainClassificationVerified",
    )
    worker_identity_policy_verified: Literal[True] = Field(
        default=True,
        alias="workerIdentityPolicyVerified",
    )
    current_activation_bound: Literal[False] = Field(
        default=False,
        alias="currentActivationBound",
    )
    campaign_authority_bound: Literal[False] = Field(
        default=False,
        alias="campaignAuthorityBound",
    )
    graph_decision_bound: Literal[False] = Field(default=False, alias="graphDecisionBound")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_bound: Literal[False] = Field(default=False, alias="permitBound")
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    profile_conformance_verified: Literal[False] = Field(
        default=False,
        alias="profileConformanceVerified",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "deployment_owned",
        "signed_release_verified",
        "capability_domain_classification_verified",
        "worker_identity_policy_verified",
        "current_activation_bound",
        "campaign_authority_bound",
        "graph_decision_bound",
        "approval_satisfied",
        "permit_bound",
        "gateway_dispatch_authorized",
        "profile_conformance_verified",
        "worker_selection_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Domain Worker deployment markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_deployment_identity(self) -> Self:
        if (
            self.capability_domain_classification.capability != self.capability.capability
            or self.capability_domain_classification.domain_classification
            != self.worker_profile.domain_classification
        ):
            raise ValueError("Domain Worker deployment authority identities differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.control-plane.domain-worker-deployment-binding/v1",
            material,
        )
        binding_id = f"domain-worker-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Domain Worker deployment binding digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Domain Worker deployment binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self

    def reference(self) -> DomainWorkerDeploymentBindingRef:
        """Return the exact detached deployment binding identity."""

        return DomainWorkerDeploymentBindingRef(
            bindingId=self.binding_id,
            bindingDigest=self.binding_digest,
            deploymentId=self.deployment_id,
        )


class DomainWorkerDeploymentRegistry(StrictModel):
    """One deployment's exact bindings, with existing execution authority still absent."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/domain-worker-deployment-registry/v1alpha1"
    ] = Field(
        default=DOMAIN_WORKER_DEPLOYMENT_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DomainWorkerDeploymentRegistry"] = "DomainWorkerDeploymentRegistry"
    registry_id: str = Field(default="", alias="registryId", max_length=87)
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    deployment_id: _Identifier = Field(alias="deploymentId")
    profile_registry_digest: _Sha256 = Field(alias="profileRegistryDigest")
    bindings: tuple[DomainWorkerDeploymentBinding, ...] = Field(min_length=1, max_length=256)
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")
    profile_catalog_bound: Literal[True] = Field(default=True, alias="profileCatalogBound")
    profile_conformance_authority_included: Literal[False] = Field(
        default=False,
        alias="profileConformanceAuthorityIncluded",
    )
    current_activation_authority_included: Literal[False] = Field(
        default=False,
        alias="currentActivationAuthorityIncluded",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "deployment_owned",
        "profile_catalog_bound",
        "profile_conformance_authority_included",
        "current_activation_authority_included",
        "permit_issuance_authorized",
        "gateway_dispatch_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Domain Worker deployment registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry_identity(self) -> Self:
        profile_registry = registered_domain_worker_boundary_profiles()
        keys = [item.binding_id for item in self.bindings]
        if (
            self.profile_registry_digest != profile_registry.registry_digest
            or any(item.deployment_id != self.deployment_id for item in self.bindings)
            or keys != sorted(set(keys))
        ):
            raise ValueError("Domain Worker deployment registry bindings differ")
        for binding in self.bindings:
            resolve_registered_domain_worker_boundary_profile(binding.worker_profile)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_id", "registry_digest"},
        )
        digest = capability_definition_digest(
            "pajin.control-plane.domain-worker-deployment-registry/v1",
            material,
        )
        registry_id = f"domain-worker-registry_{digest}"
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Domain Worker deployment registry digest differs")
        if self.registry_id and self.registry_id != registry_id:
            raise ValueError("Domain Worker deployment registry ID differs")
        object.__setattr__(self, "registry_digest", digest)
        object.__setattr__(self, "registry_id", registry_id)
        return self


@dataclass(frozen=True, slots=True)
class _WorkerBoundarySpec:
    domain: SecurityDomain
    network_boundary: WorkerNetworkBoundary
    filesystem_boundary: WorkerFilesystemBoundary
    credential_boundary: WorkerCredentialBoundary
    runtime_boundary: WorkerRuntimeBoundary
    required_identity_dimensions: tuple[str, ...]
    required_budget_dimensions: tuple[str, ...]
    protocol_privilege_review_required: bool = False
    provenance_preservation_required: bool = False

    @property
    def profile_id(self) -> str:
        return f"pajin.worker-boundary.{self.domain.value}.minimum"


_PROFILE_SPECS = (
    _WorkerBoundarySpec(
        SecurityDomain.WEB,
        WorkerNetworkBoundary.BOUNDED_EGRESS,
        WorkerFilesystemBoundary.NO_HOST_ACCESS,
        WorkerCredentialBoundary.NONE,
        WorkerRuntimeBoundary.ISOLATED_NON_ROOT,
        ("http-method", "http-target"),
        ("request-count", "response-bytes", "runtime"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.NETWORK,
        WorkerNetworkBoundary.EXACT_HOST_PROTOCOL_PORT,
        WorkerFilesystemBoundary.NO_HOST_ACCESS,
        WorkerCredentialBoundary.NONE,
        WorkerRuntimeBoundary.ISOLATED_NON_ROOT,
        ("address-family", "host", "port", "protocol"),
        ("probe-count", "response-bytes", "runtime"),
        True,
    ),
    _WorkerBoundarySpec(
        SecurityDomain.SYSTEM,
        WorkerNetworkBoundary.DEPLOYMENT_SCOPED,
        WorkerFilesystemBoundary.BOUNDED_HOST_READ,
        WorkerCredentialBoundary.DEPLOYMENT_AUTHENTICATION,
        WorkerRuntimeBoundary.AUTHENTICATED_NON_ROOT_AGENT,
        ("authorized-host", "host-agent"),
        ("artifact-bytes", "runtime"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.APPLICATION,
        WorkerNetworkBoundary.DISABLED_BY_DEFAULT,
        WorkerFilesystemBoundary.READ_ONLY_ARTIFACT,
        WorkerCredentialBoundary.NONE,
        WorkerRuntimeBoundary.OFFLINE_SANDBOX,
        ("analyzer", "artifact-digest"),
        ("artifact-bytes", "runtime"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.MOBILE,
        WorkerNetworkBoundary.DISABLED_BY_DEFAULT,
        WorkerFilesystemBoundary.READ_ONLY_ARTIFACT,
        WorkerCredentialBoundary.NONE,
        WorkerRuntimeBoundary.DEVICE_BOUND,
        ("app-identity", "artifact-digest", "emulator-or-device"),
        ("artifact-bytes", "runtime"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.CLOUD,
        WorkerNetworkBoundary.BOUNDED_EGRESS,
        WorkerFilesystemBoundary.NO_HOST_ACCESS,
        WorkerCredentialBoundary.EPHEMERAL_LEASE,
        WorkerRuntimeBoundary.ISOLATED_NON_ROOT,
        ("account-or-project", "credential-lease", "resource"),
        ("credential-ttl", "request-count", "runtime"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.AI,
        WorkerNetworkBoundary.BOUNDED_EGRESS,
        WorkerFilesystemBoundary.NO_HOST_ACCESS,
        WorkerCredentialBoundary.EPHEMERAL_LEASE,
        WorkerRuntimeBoundary.ISOLATED_NON_ROOT,
        ("ai-surface", "model", "provider", "tool"),
        ("cost", "request-count", "token-count"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.CRYPTOGRAPHY,
        WorkerNetworkBoundary.DISABLED_BY_DEFAULT,
        WorkerFilesystemBoundary.READ_ONLY_ARTIFACT,
        WorkerCredentialBoundary.NONE,
        WorkerRuntimeBoundary.OFFLINE_SANDBOX,
        ("analyzer", "artifact-digest"),
        ("artifact-bytes", "runtime"),
    ),
    _WorkerBoundarySpec(
        SecurityDomain.FORENSICS,
        WorkerNetworkBoundary.DISABLED_BY_DEFAULT,
        WorkerFilesystemBoundary.IMMUTABLE_EVIDENCE,
        WorkerCredentialBoundary.NONE,
        WorkerRuntimeBoundary.PROVENANCE_PRESERVING_PARSER,
        ("evidence-source", "parser"),
        ("artifact-bytes", "runtime"),
        False,
        True,
    ),
)


def registered_domain_worker_boundary_profiles() -> DomainWorkerBoundaryProfileRegistry:
    """Return the exact code-owned minimum profile catalog."""

    return DomainWorkerBoundaryProfileRegistry(profiles=_registered_profiles())


def resolve_registered_domain_worker_boundary_profile(
    reference: DomainWorkerBoundaryProfileRef,
) -> RegisteredDomainWorkerBoundaryProfile:
    """Resolve only an exact profile reference without selecting a Worker."""

    for profile in registered_domain_worker_boundary_profiles().profiles:
        if profile.reference() == reference:
            return profile.model_copy(deep=True)
    raise DomainWorkerBoundaryError("Domain Worker boundary profile is not registered exactly")


def register_domain_worker_deployment_binding(
    *,
    deployment_id: str,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
    capability_domain_classification: CapabilityDomainClassificationRef,
    worker_profile: DomainWorkerBoundaryProfileRef,
    worker_mtls_policy: WorkerMTLSTrustPolicy,
    worker_subject: str,
    existing_bundle: ExistingModeCapabilityBundle,
    pentest_recon_bundle: PentestReconCapabilityBundle,
) -> DomainWorkerDeploymentBinding:
    """Bind a verified signed release to one exact deployment-owned Worker identity."""

    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Domain Worker deployment requires a Capability lifecycle registry")
    if not isinstance(worker_mtls_policy, WorkerMTLSTrustPolicy):
        raise TypeError("Domain Worker deployment requires a Worker mTLS policy")
    try:
        canonical_worker_policy = WorkerMTLSTrustPolicy.model_validate(
            worker_mtls_policy.model_dump(mode="json")
        )
    except (AttributeError, ValidationError) as exc:
        raise DomainWorkerBoundaryError(
            "Domain Worker deployment mTLS policy is not canonical"
        ) from exc
    classification = _resolve_capability_domain_classification(
        capability_domain_classification,
        existing_bundle=existing_bundle,
        pentest_recon_bundle=pentest_recon_bundle,
    )
    profile = resolve_registered_domain_worker_boundary_profile(worker_profile)
    try:
        signed_bundle = lifecycle.resolve_release(release)
    except CapabilityLifecycleError as exc:
        raise DomainWorkerBoundaryError(
            "Domain Worker deployment release is not signed and registered exactly"
        ) from exc
    statement = signed_bundle.release.statement
    if (
        statement.reference() != release
        or statement.capability != classification.code_backed_capability
        or profile.domain_classification != classification.domain_classification
    ):
        raise DomainWorkerBoundaryError(
            "Domain Worker deployment release, Capability, and profile differ"
        )
    identities = {
        item.principal_subject: item for item in canonical_worker_policy.bindings
    }
    try:
        worker_identity = identities[worker_subject]
    except KeyError as exc:
        raise DomainWorkerBoundaryError(
            "Domain Worker identity is not bound by the deployment mTLS policy"
        ) from exc
    return DomainWorkerDeploymentBinding(
        deploymentId=deployment_id,
        capability=classification.code_backed_capability,
        capabilityRelease=release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capabilityDomainClassification=classification.reference(),
        workerProfile=profile.reference(),
        workerMTLSPolicyId=canonical_worker_policy.policy_id,
        workerMTLSPolicyDigest=_worker_mtls_policy_digest(canonical_worker_policy),
        workerIdentity=worker_identity,
    )


def build_domain_worker_deployment_registry(
    *,
    deployment_id: str,
    bindings: Iterable[DomainWorkerDeploymentBinding],
) -> DomainWorkerDeploymentRegistry:
    """Build one exact deployment registry without activation or execution authority."""

    canonical: list[DomainWorkerDeploymentBinding] = []
    for binding in bindings:
        try:
            canonical.append(
                DomainWorkerDeploymentBinding.model_validate(
                    binding.model_dump(mode="json", by_alias=True)
                )
            )
        except (AttributeError, ValidationError) as exc:
            raise DomainWorkerBoundaryError(
                "Domain Worker deployment binding is not canonical"
            ) from exc
    if not canonical:
        raise DomainWorkerBoundaryError("Domain Worker deployment registry is empty")
    profile_registry = registered_domain_worker_boundary_profiles()
    return DomainWorkerDeploymentRegistry(
        deploymentId=deployment_id,
        profileRegistryDigest=profile_registry.registry_digest,
        bindings=tuple(sorted(canonical, key=lambda item: item.binding_id)),
    )


def resolve_domain_worker_deployment_binding(
    reference: DomainWorkerDeploymentBindingRef,
    *,
    registry: DomainWorkerDeploymentRegistry,
) -> DomainWorkerDeploymentBinding:
    """Resolve an exact binding reference; Domain labels are never lookup authority."""

    try:
        canonical = DomainWorkerDeploymentRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise DomainWorkerBoundaryError(
            "Domain Worker deployment registry is not canonical"
        ) from exc
    for binding in canonical.bindings:
        if binding.reference() == reference:
            return binding.model_copy(deep=True)
    raise DomainWorkerBoundaryError("Domain Worker deployment binding is not registered exactly")


def _registered_profiles() -> tuple[RegisteredDomainWorkerBoundaryProfile, ...]:
    return tuple(
        RegisteredDomainWorkerBoundaryProfile(
            domainClassification=_domain_classification(spec.domain),
            networkBoundary=spec.network_boundary,
            filesystemBoundary=spec.filesystem_boundary,
            credentialBoundary=spec.credential_boundary,
            runtimeBoundary=spec.runtime_boundary,
            requiredIdentityDimensions=spec.required_identity_dimensions,
            requiredBudgetDimensions=spec.required_budget_dimensions,
            protocolPrivilegeReviewRequired=spec.protocol_privilege_review_required,
            provenancePreservationRequired=spec.provenance_preservation_required,
        )
        for spec in _PROFILE_SPECS
    )


def _profile_spec(domain: SecurityDomain) -> _WorkerBoundarySpec:
    for spec in _PROFILE_SPECS:
        if spec.domain is domain:
            return spec
    raise ValueError("Domain Worker boundary profile is not code registered")


def _domain_classification(domain: SecurityDomain) -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(item.reference() for item in taxonomy.domains if item.domain is domain)


def _resolve_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
    *,
    existing_bundle: ExistingModeCapabilityBundle,
    pentest_recon_bundle: PentestReconCapabilityBundle,
) -> RegisteredCapabilityDomainClassification:
    try:
        return resolve_registered_capability_domain_classification(
            reference,
            existing_bundle=existing_bundle,
            pentest_recon_bundle=pentest_recon_bundle,
        )
    except CapabilityDomainProjectionError as exc:
        raise DomainWorkerBoundaryError(
            "Domain Worker deployment Capability classification is not registered exactly"
        ) from exc


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.control-plane.domain-worker-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _worker_mtls_policy_digest(policy: WorkerMTLSTrustPolicy) -> str:
    return capability_definition_digest(
        "pajin.control-plane.domain-worker-mtls-policy/v1",
        policy.model_dump(mode="json"),
    )
