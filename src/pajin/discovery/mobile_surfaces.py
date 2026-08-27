"""MOBILE-001A typed Mobile Surfaces without package or device authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

import idna
from pydantic import ConfigDict, Field, TypeAdapter, field_validator, model_validator

from pajin.discovery.application_surfaces import (
    ApplicationBinarySurfaceLocator,
    application_binary_surface_locator,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import DISCOVERY_API_VERSION
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SECURITY_DOMAIN_TAXONOMY_API_VERSION,
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)
from pajin.graph.domain_semantics import (
    MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
    SecurityDomainGraphTypeSetRef,
    registered_multi_domain_graph_semantics,
)

MOBILE_APPLICATION_RUNTIME_LOCATOR_API_VERSION: Literal[
    "pajin.dev/mobile-application-runtime-locator/v1alpha1"
] = "pajin.dev/mobile-application-runtime-locator/v1alpha1"
MOBILE_APPLICATION_RUNTIME_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/mobile-application-runtime-locator-registry/v1alpha1"
] = "pajin.dev/mobile-application-runtime-locator-registry/v1alpha1"
MOBILE_APPLICATION_RUNTIME_SURFACE_API_VERSION: Literal[
    "pajin.dev/mobile-application-runtime-surface/v1alpha1"
] = "pajin.dev/mobile-application-runtime-surface/v1alpha1"

MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE: Literal["mobile.application-runtime"] = (
    "mobile.application-runtime"
)
MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA: Literal[
    "pajin.locator.mobile.application-runtime.v1"
] = "pajin.locator.mobile.application-runtime.v1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_ApplicationId = Annotated[
    str,
    Field(min_length=3, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,254}$"),
]
_Coordinate = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._+-]{0,127}$"),
]
_RuntimeVersion = Annotated[
    str,
    Field(
        min_length=1,
        max_length=96,
        pattern=r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*$",
    ),
]
_Scheme = Annotated[
    str,
    Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9+.-]{0,31}$"),
]
_Host = Annotated[str, Field(min_length=1, max_length=253)]
_Port = Annotated[int, Field(ge=1, le=65_535)]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^mobile-application-runtime-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 512 * 1024
_MAX_TYPED_SURFACE_BYTES = 512 * 1024
_MUTABLE_COORDINATE_TOKENS = frozenset(
    {
        "any",
        "auto",
        "current",
        "default",
        "latest",
        "local",
        "stable",
        "unknown",
        "x",
    }
)


class MobileSurfaceRegistryError(RuntimeError):
    """Raised when an exact MOBILE-001A registry reference cannot be resolved."""


class MobileSurfaceClass(StrEnum):
    """Mobile knowledge classes that grant no package-analysis or device authority."""

    APK = "apk"
    IPA = "ipa"
    APPLICATION = "application"
    RUNTIME = "runtime"
    STORAGE = "storage"
    DEEPLINK = "deeplink"
    TLS = "tls"
    AUTH = "auth"


class MobilePlatform(StrEnum):
    """Package platform declared by an exact APK or IPA coordinate."""

    ANDROID = "android"
    IOS = "ios"


class MobileRuntimeDeclarationKind(StrEnum):
    """Bounded runtime declaration vocabulary, not a live runtime claim."""

    MINIMUM_SUPPORTED = "minimum-supported"
    TARGET = "target"


class MobileStorageKind(StrEnum):
    """Platform-neutral logical storage classes without path or value content."""

    PREFERENCES = "preferences"
    DATABASE = "database"
    FILE = "file"
    CACHE = "cache"
    SECURE_STORE = "secure-store"


class MobileDeepLinkKind(StrEnum):
    """Declared link-association classes without a full URI or route path."""

    CUSTOM_SCHEME = "custom-scheme"
    ANDROID_APP_LINK = "android-app-link"
    IOS_UNIVERSAL_LINK = "ios-universal-link"


class MobileTLSPolicyKind(StrEnum):
    """Sanitized TLS-policy classes without certificate, key, or pin material."""

    ANDROID_NETWORK_SECURITY_CONFIG = "android-network-security-config"
    IOS_APP_TRANSPORT_SECURITY = "ios-app-transport-security"
    CERTIFICATE_PINNING = "certificate-pinning"
    CUSTOM = "custom"


class MobileAuthenticationKind(StrEnum):
    """Sanitized authentication-flow classes without endpoint or credential content."""

    LOCAL = "local"
    FEDERATED = "federated"
    BIOMETRIC = "biometric"
    DEVICE_CREDENTIAL = "device-credential"
    CUSTOM = "custom"


class _SecretFreeMobileLocator(StrictModel):
    """Negative markers shared by package-content-free Mobile locators."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    package_bytes_embedded: Literal[False] = Field(default=False, alias="packageBytesEmbedded")
    manifest_embedded: Literal[False] = Field(default=False, alias="manifestEmbedded")
    signing_material_embedded: Literal[False] = Field(
        default=False,
        alias="signingMaterialEmbedded",
    )
    raw_security_configuration_embedded: Literal[False] = Field(
        default=False,
        alias="rawSecurityConfigurationEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )
    device_state_embedded: Literal[False] = Field(default=False, alias="deviceStateEmbedded")
    device_local_path_embedded: Literal[False] = Field(
        default=False,
        alias="deviceLocalPathEmbedded",
    )

    @field_validator(
        "package_bytes_embedded",
        "manifest_embedded",
        "signing_material_embedded",
        "raw_security_configuration_embedded",
        "secret_material_embedded",
        "credential_reference_embedded",
        "device_state_embedded",
        "device_local_path_embedded",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mobile locator security markers must be boolean false")
        return value


class MobileAPKSurfaceLocator(_SecretFreeMobileLocator):
    """One caller-declared APK package below an exact Application binary coordinate."""

    kind: Literal["mobile-apk-package"] = "mobile-apk-package"
    application_artifact: ApplicationBinarySurfaceLocator = Field(alias="applicationArtifact")

    @model_validator(mode="after")
    def require_exact_application_artifact(self) -> Self:
        _require_exact_application_binary(self.application_artifact)
        return self


class MobileIPASurfaceLocator(_SecretFreeMobileLocator):
    """One caller-declared IPA package below an exact Application binary coordinate."""

    kind: Literal["mobile-ipa-package"] = "mobile-ipa-package"
    application_artifact: ApplicationBinarySurfaceLocator = Field(alias="applicationArtifact")

    @model_validator(mode="after")
    def require_exact_application_artifact(self) -> Self:
        _require_exact_application_binary(self.application_artifact)
        return self


MobilePackageSurfaceLocator = Annotated[
    MobileAPKSurfaceLocator | MobileIPASurfaceLocator,
    Field(discriminator="kind"),
]
_MOBILE_PACKAGE_ADAPTER: TypeAdapter[MobilePackageSurfaceLocator] = TypeAdapter(
    MobilePackageSurfaceLocator
)


class MobileApplicationSurfaceLocator(_SecretFreeMobileLocator):
    """One exact platform-valid application ID below an exact package lineage."""

    kind: Literal["mobile-application"] = "mobile-application"
    parent: MobilePackageSurfaceLocator
    application_id: _ApplicationId = Field(alias="applicationId")

    @model_validator(mode="after")
    def bind_application_to_package_platform(self) -> Self:
        parent = _validated_mobile_package(self.parent)
        platform = _mobile_package_platform(parent)
        if platform is MobilePlatform.ANDROID:
            valid = re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+",
                self.application_id,
            )
        else:
            valid = re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+",
                self.application_id,
            )
        if valid is None:
            raise ValueError("Mobile application ID is not canonical for its package platform")
        if platform is MobilePlatform.IOS:
            object.__setattr__(self, "application_id", self.application_id.casefold())
        return self


class _MobileApplicationChildLocator(_SecretFreeMobileLocator):
    """Base for exact Mobile application children."""

    parent: MobileApplicationSurfaceLocator

    @model_validator(mode="after")
    def require_exact_application_parent(self) -> Self:
        _validated_mobile_application(self.parent)
        return self


class MobileRuntimeSurfaceLocator(_MobileApplicationChildLocator):
    """One declared platform runtime requirement, never a live device runtime."""

    kind: Literal["mobile-runtime"] = "mobile-runtime"
    runtime_family: MobilePlatform = Field(alias="runtimeFamily")
    declaration_kind: MobileRuntimeDeclarationKind = Field(alias="declarationKind")
    runtime_version: _RuntimeVersion = Field(alias="runtimeVersion")

    @field_validator("runtime_version", mode="before")
    @classmethod
    def canonicalize_runtime_version(cls, value: object) -> object:
        return _canonical_exact_runtime_version(value)

    @model_validator(mode="after")
    def bind_runtime_to_package_platform(self) -> Self:
        if self.runtime_family is not _mobile_application_platform(self.parent):
            raise ValueError("Mobile runtime family differs from the exact package platform")
        if self.runtime_family is MobilePlatform.ANDROID and "." in self.runtime_version:
            raise ValueError("Android runtime version must be one exact numeric API level")
        return self


class MobileStorageSurfaceLocator(_MobileApplicationChildLocator):
    """One logical storage declaration without device path, stored value, or access authority."""

    kind: Literal["mobile-storage"] = "mobile-storage"
    storage_kind: MobileStorageKind = Field(alias="storageKind")
    storage_id: _Coordinate = Field(alias="storageId")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")

    @field_validator("storage_id", mode="before")
    @classmethod
    def canonicalize_storage_id(cls, value: object) -> object:
        return _canonical_mobile_coordinate(value, label="Mobile storage ID")


class MobileDeepLinkSurfaceLocator(_MobileApplicationChildLocator):
    """One sanitized deep-link declaration without a full URI, path, query, or fragment."""

    kind: Literal["mobile-deeplink"] = "mobile-deeplink"
    link_kind: MobileDeepLinkKind = Field(alias="linkKind")
    scheme: _Scheme
    host: _Host | None = None
    port: _Port | None = None
    route_id: _Coordinate = Field(alias="routeId")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")

    @field_validator("scheme", mode="before")
    @classmethod
    def canonicalize_scheme(cls, value: object) -> object:
        return _canonical_mobile_scheme(value)

    @field_validator("host", mode="before")
    @classmethod
    def canonicalize_host(cls, value: object) -> object:
        return _canonical_mobile_host(value)

    @field_validator("port", mode="before")
    @classmethod
    def require_exact_port(cls, value: object) -> object:
        if value is not None and type(value) is not int:
            raise ValueError("Mobile deep-link port must be an integer")
        return value

    @field_validator("route_id", mode="before")
    @classmethod
    def canonicalize_route_id(cls, value: object) -> object:
        return _canonical_mobile_coordinate(value, label="Mobile deep-link route ID")

    @model_validator(mode="after")
    def bind_link_to_package_platform(self) -> Self:
        platform = _mobile_application_platform(self.parent)
        if self.port is not None and self.host is None:
            raise ValueError("Mobile deep-link port requires an exact host")
        if self.link_kind is MobileDeepLinkKind.CUSTOM_SCHEME:
            if self.scheme in {"http", "https"}:
                raise ValueError("Custom Mobile deep links cannot use HTTP schemes")
        else:
            if self.scheme not in {"http", "https"} or self.host is None:
                raise ValueError("App and universal links require an HTTP scheme and exact host")
            if (
                self.link_kind is MobileDeepLinkKind.ANDROID_APP_LINK
                and platform is not MobilePlatform.ANDROID
            ) or (
                self.link_kind is MobileDeepLinkKind.IOS_UNIVERSAL_LINK
                and platform is not MobilePlatform.IOS
            ):
                raise ValueError("Mobile deep-link kind differs from the exact package platform")
        return self


class MobileTLSPolicySurfaceLocator(_MobileApplicationChildLocator):
    """One sanitized TLS-policy declaration without endpoint, certificate, key, or pin values."""

    kind: Literal["mobile-tls-policy"] = "mobile-tls-policy"
    policy_kind: MobileTLSPolicyKind = Field(alias="policyKind")
    policy_id: _Coordinate = Field(alias="policyId")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")

    @field_validator("policy_id", mode="before")
    @classmethod
    def canonicalize_policy_id(cls, value: object) -> object:
        return _canonical_mobile_coordinate(value, label="Mobile TLS policy ID")

    @model_validator(mode="after")
    def bind_policy_to_package_platform(self) -> Self:
        platform = _mobile_application_platform(self.parent)
        if (
            self.policy_kind is MobileTLSPolicyKind.ANDROID_NETWORK_SECURITY_CONFIG
            and platform is not MobilePlatform.ANDROID
        ) or (
            self.policy_kind is MobileTLSPolicyKind.IOS_APP_TRANSPORT_SECURITY
            and platform is not MobilePlatform.IOS
        ):
            raise ValueError("Mobile TLS policy kind differs from the exact package platform")
        return self


class MobileAuthenticationSurfaceLocator(_MobileApplicationChildLocator):
    """One sanitized authentication-flow declaration without endpoint or credential values."""

    kind: Literal["mobile-authentication"] = "mobile-authentication"
    authentication_kind: MobileAuthenticationKind = Field(alias="authenticationKind")
    flow_id: _Coordinate = Field(alias="flowId")
    declaration_sha256: _Sha256 = Field(alias="declarationSha256")

    @field_validator("flow_id", mode="before")
    @classmethod
    def canonicalize_flow_id(cls, value: object) -> object:
        return _canonical_mobile_coordinate(value, label="Mobile authentication flow ID")


MobileApplicationRuntimeSurfaceLocator = Annotated[
    MobileAPKSurfaceLocator
    | MobileIPASurfaceLocator
    | MobileApplicationSurfaceLocator
    | MobileRuntimeSurfaceLocator
    | MobileStorageSurfaceLocator
    | MobileDeepLinkSurfaceLocator
    | MobileTLSPolicySurfaceLocator
    | MobileAuthenticationSurfaceLocator,
    Field(discriminator="kind"),
]
_MOBILE_LOCATOR_ADAPTER: TypeAdapter[MobileApplicationRuntimeSurfaceLocator] = TypeAdapter(
    MobileApplicationRuntimeSurfaceLocator
)

MobileSurfaceLocatorKind = Literal[
    "mobile-apk-package",
    "mobile-ipa-package",
    "mobile-application",
    "mobile-runtime",
    "mobile-storage",
    "mobile-deeplink",
    "mobile-tls-policy",
    "mobile-authentication",
]
MobileParentRequirement = Literal[
    "application-binary",
    "mobile-package",
    "mobile-application",
]
MobilePlatformRequirement = Literal["android", "ios", "from-parent"]


@dataclass(frozen=True, slots=True)
class _MobileLocatorSpec:
    locator_id: str
    locator_kind: MobileSurfaceLocatorKind
    surface_class: MobileSurfaceClass
    source_model_id: str
    parent_requirement: MobileParentRequirement
    platform_requirement: MobilePlatformRequirement
    declaration_digest_required: bool
    exact_version_required: bool


_MOBILE_LOCATOR_SPECS = (
    _MobileLocatorSpec(
        "pajin.locator.mobile.apk-package",
        "mobile-apk-package",
        MobileSurfaceClass.APK,
        "pajin.discovery.mobile_surfaces.MobileAPKSurfaceLocator",
        "application-binary",
        "android",
        False,
        False,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.ipa-package",
        "mobile-ipa-package",
        MobileSurfaceClass.IPA,
        "pajin.discovery.mobile_surfaces.MobileIPASurfaceLocator",
        "application-binary",
        "ios",
        False,
        False,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.application",
        "mobile-application",
        MobileSurfaceClass.APPLICATION,
        "pajin.discovery.mobile_surfaces.MobileApplicationSurfaceLocator",
        "mobile-package",
        "from-parent",
        False,
        False,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.runtime",
        "mobile-runtime",
        MobileSurfaceClass.RUNTIME,
        "pajin.discovery.mobile_surfaces.MobileRuntimeSurfaceLocator",
        "mobile-application",
        "from-parent",
        False,
        True,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.storage",
        "mobile-storage",
        MobileSurfaceClass.STORAGE,
        "pajin.discovery.mobile_surfaces.MobileStorageSurfaceLocator",
        "mobile-application",
        "from-parent",
        True,
        False,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.deeplink",
        "mobile-deeplink",
        MobileSurfaceClass.DEEPLINK,
        "pajin.discovery.mobile_surfaces.MobileDeepLinkSurfaceLocator",
        "mobile-application",
        "from-parent",
        True,
        False,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.tls-policy",
        "mobile-tls-policy",
        MobileSurfaceClass.TLS,
        "pajin.discovery.mobile_surfaces.MobileTLSPolicySurfaceLocator",
        "mobile-application",
        "from-parent",
        True,
        False,
    ),
    _MobileLocatorSpec(
        "pajin.locator.mobile.authentication",
        "mobile-authentication",
        MobileSurfaceClass.AUTH,
        "pajin.discovery.mobile_surfaces.MobileAuthenticationSurfaceLocator",
        "mobile-application",
        "from-parent",
        True,
        False,
    ),
)


class MobileApplicationRuntimeLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered Mobile locator."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: MobileSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: MobileSurfaceClass = Field(alias="surfaceClass")

    @model_validator(mode="after")
    def bind_registered_locator_reference(self) -> Self:
        registered = next(
            (item for item in _registered_mobile_locators() if item.locator_id == self.locator_id),
            None,
        )
        if registered is None or (
            self.locator_version,
            self.locator_digest,
            self.locator_kind,
            self.surface_class,
        ) != (
            registered.locator_version,
            registered.locator_digest,
            registered.locator_kind,
            registered.surface_class,
        ):
            raise ValueError("Mobile locator reference differs from code authority")
        return self


class MobileApplicationRuntimeLocatorRegistryRef(StrictModel):
    """Exact reference to the complete MOBILE-001A locator registry."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    registry_id: Literal["pajin.mobile.application-runtime-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")

    @model_validator(mode="after")
    def bind_registered_registry_reference(self) -> Self:
        if (
            self.registry_id,
            self.registry_version,
            self.registry_digest,
        ) != _mobile_locator_registry_identity():
            raise ValueError("Mobile locator registry reference differs from code authority")
        return self


class MobileApplicationRuntimeSurfaceRef(StrictModel):
    """Exact reference to one inert typed Mobile Surface."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["mobile.application-runtime"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.mobile.application-runtime.v1"] = Field(
        alias="locatorSchema"
    )
    surface_class: MobileSurfaceClass = Field(alias="surfaceClass")
    locator_kind: MobileSurfaceLocatorKind = Field(alias="locatorKind")
    locator_registry: MobileApplicationRuntimeLocatorRegistryRef = Field(alias="locatorRegistry")

    @model_validator(mode="after")
    def bind_surface_reference(self) -> Self:
        registered = next(
            (
                item
                for item in _registered_mobile_locators()
                if item.locator_kind == self.locator_kind
            ),
            None,
        )
        if (
            self.surface_id != f"mobile-application-runtime-surface_{self.surface_digest}"
            or registered is None
            or registered.surface_class is not self.surface_class
            or (
                self.locator_registry.registry_id,
                self.locator_registry.registry_version,
                self.locator_registry.registry_digest,
            )
            != _mobile_locator_registry_identity()
        ):
            raise ValueError("Mobile Surface reference differs from code authority")
        return self


class _NoMobileAuthority(StrictModel):
    """Authority markers that remain literal false throughout MOBILE-001A."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        revalidate_instances="always",
    )

    artifact_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="artifactResolutionAuthorized",
    )
    package_read_authorized: Literal[False] = Field(default=False, alias="packageReadAuthorized")
    static_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="staticAnalysisAuthorized",
    )
    sandbox_selection_authorized: Literal[False] = Field(
        default=False,
        alias="sandboxSelectionAuthorized",
    )
    emulator_selection_authorized: Literal[False] = Field(
        default=False,
        alias="emulatorSelectionAuthorized",
    )
    device_selection_authorized: Literal[False] = Field(
        default=False,
        alias="deviceSelectionAuthorized",
    )
    device_access_authorized: Literal[False] = Field(
        default=False,
        alias="deviceAccessAuthorized",
    )
    instrumentation_authorized: Literal[False] = Field(
        default=False,
        alias="instrumentationAuthorized",
    )
    dynamic_analysis_authorized: Literal[False] = Field(
        default=False,
        alias="dynamicAnalysisAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    tls_validation_authorized: Literal[False] = Field(
        default=False,
        alias="tlsValidationAuthorized",
    )
    authentication_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="authenticationInvocationAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    storage_read_authorized: Literal[False] = Field(
        default=False,
        alias="storageReadAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    package_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="packageMutationAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "artifact_resolution_authorized",
        "package_read_authorized",
        "static_analysis_authorized",
        "sandbox_selection_authorized",
        "emulator_selection_authorized",
        "device_selection_authorized",
        "device_access_authorized",
        "instrumentation_authorized",
        "dynamic_analysis_authorized",
        "network_access_authorized",
        "tls_validation_authorized",
        "authentication_invocation_authorized",
        "credential_access_authorized",
        "storage_read_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "graph_admission_authorized",
        "finding_authority",
        "package_mutation_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("MOBILE-001A authority markers must be boolean false")
        return value


class RegisteredMobileApplicationRuntimeLocator(_NoMobileAuthority):
    """One code-owned Mobile locator mapping without package or device authority."""

    api_version: Literal["pajin.dev/mobile-application-runtime-locator/v1alpha1"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredMobileApplicationRuntimeLocator"] = (
        "RegisteredMobileApplicationRuntimeLocator"
    )
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: MobileSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: MobileSurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    parent_requirement: MobileParentRequirement = Field(alias="parentRequirement")
    platform_requirement: MobilePlatformRequirement = Field(alias="platformRequirement")
    declaration_digest_required: bool = Field(alias="declarationDigestRequired")
    exact_version_required: bool = Field(alias="exactVersionRequired")
    secret_free: Literal[True] = Field(default=True, alias="secretFree")
    full_parent_lineage_required: Literal[True] = Field(
        default=True,
        alias="fullParentLineageRequired",
    )
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")

    @field_validator(
        "declaration_digest_required",
        "exact_version_required",
        "secret_free",
        "full_parent_lineage_required",
        "locator_schema_implementation_available",
        "registration_only",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _MOBILE_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.parent_requirement,
                self.platform_requirement,
                self.declaration_digest_required,
                self.exact_version_required,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.parent_requirement,
                spec.platform_requirement,
                spec.declaration_digest_required,
                spec.exact_version_required,
            )
            or self.domain_classification != _mobile_domain_classification()
            or self.domain_graph_type_set != _mobile_graph_type_set()
        ):
            raise ValueError("Mobile application/runtime locator differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"locator_digest"})
        canonical_json_bytes(
            material,
            label="Mobile application/runtime locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.mobile-application-runtime-locator/v1",
            material,
        )
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Mobile application/runtime locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> MobileApplicationRuntimeLocatorRef:
        """Return the exact locator reference without authority transfer."""

        canonical = _validated_registered_mobile_locator(self)
        return MobileApplicationRuntimeLocatorRef(
            locatorId=canonical.locator_id,
            locatorVersion=canonical.locator_version,
            locatorDigest=canonical.locator_digest,
            locatorKind=canonical.locator_kind,
            surfaceClass=canonical.surface_class,
        )


class MobileApplicationRuntimeLocatorRegistry(_NoMobileAuthority):
    """Complete MOBILE-001A locator registry without package or device authority."""

    api_version: Literal["pajin.dev/mobile-application-runtime-locator-registry/v1alpha1"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_LOCATOR_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobileApplicationRuntimeLocatorRegistry"] = (
        "MobileApplicationRuntimeLocatorRegistry"
    )
    registry_id: Literal["pajin.mobile.application-runtime-locators"] = Field(
        default="pajin.mobile.application-runtime-locators",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal["pajin.dev/security-domain-taxonomy/v1alpha1"] = (
        Field(
            default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
            alias="securityDomainTaxonomyApiVersion",
        )
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    multi_domain_graph_semantics_api_version: Literal[
        "pajin.dev/multi-domain-graph-semantics/v1alpha1"
    ] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="multiDomainGraphSemanticsApiVersion",
    )
    multi_domain_graph_semantics_digest: _Sha256 = Field(alias="multiDomainGraphSemanticsDigest")
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["mobile.application-runtime"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.mobile.application-runtime.v1"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredMobileApplicationRuntimeLocator, ...] = Field(
        min_length=len(_MOBILE_LOCATOR_SPECS),
        max_length=len(_MOBILE_LOCATOR_SPECS),
    )
    discovered_surface_initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="discoveredSurfaceInitialState",
    )
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    discovery_wire_changed: Literal[False] = Field(
        default=False,
        alias="discoveryWireChanged",
    )
    attack_surface_wire_changed: Literal[False] = Field(
        default=False,
        alias="attackSurfaceWireChanged",
    )
    domain_semantics_registry_changed: Literal[False] = Field(
        default=False,
        alias="domainSemanticsRegistryChanged",
    )

    @field_validator(
        "registry_only",
        "discovery_wire_changed",
        "attack_surface_wire_changed",
        "domain_semantics_registry_changed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Mobile locator registry boundary markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        for locator in self.locators:
            _require_known_instance_fields(
                locator,
                label="Registered Mobile locator",
            )
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _mobile_domain_classification()
            or self.domain_graph_type_set != _mobile_graph_type_set()
            or self.locators != _registered_mobile_locators()
            or tuple(item.surface_class for item in self.locators) != tuple(MobileSurfaceClass)
        ):
            raise ValueError(
                "Mobile application/runtime locator registry differs from code authority"
            )
        material = self.model_dump(mode="json", by_alias=True, exclude={"registry_digest"})
        canonical_json_bytes(
            material,
            label="Mobile application/runtime locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.mobile-application-runtime-registry/v1",
            material,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Mobile application/runtime locator registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> MobileApplicationRuntimeLocatorRegistryRef:
        """Return the exact complete registry reference."""

        canonical = _validated_mobile_locator_registry(self)
        return MobileApplicationRuntimeLocatorRegistryRef(
            registryId=canonical.registry_id,
            registryVersion=canonical.registry_version,
            registryDigest=canonical.registry_digest,
        )


class MobileApplicationRuntimeSurface(_NoMobileAuthority):
    """Typed Mobile knowledge that is neither package-analyzed nor Graph-admitted."""

    api_version: Literal["pajin.dev/mobile-application-runtime-surface/v1alpha1"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MobileApplicationRuntimeSurface"] = "MobileApplicationRuntimeSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=110)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["mobile.application-runtime"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.mobile.application-runtime.v1"] = Field(
        default=MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: MobileSurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: MobileApplicationRuntimeLocatorRegistryRef = Field(alias="locatorRegistry")
    locator: MobileApplicationRuntimeSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    package_resolved: Literal[False] = Field(default=False, alias="packageResolved")
    package_bytes_verified: Literal[False] = Field(default=False, alias="packageBytesVerified")
    package_format_verified: Literal[False] = Field(default=False, alias="packageFormatVerified")
    manifest_verified: Literal[False] = Field(default=False, alias="manifestVerified")
    application_identity_verified: Literal[False] = Field(
        default=False,
        alias="applicationIdentityVerified",
    )
    signing_identity_verified: Literal[False] = Field(
        default=False,
        alias="signingIdentityVerified",
    )
    runtime_declaration_verified: Literal[False] = Field(
        default=False,
        alias="runtimeDeclarationVerified",
    )
    storage_declaration_verified: Literal[False] = Field(
        default=False,
        alias="storageDeclarationVerified",
    )
    deep_link_declaration_verified: Literal[False] = Field(
        default=False,
        alias="deepLinkDeclarationVerified",
    )
    tls_policy_verified: Literal[False] = Field(default=False, alias="tlsPolicyVerified")
    authentication_flow_verified: Literal[False] = Field(
        default=False,
        alias="authenticationFlowVerified",
    )
    device_identity_verified: Literal[False] = Field(
        default=False,
        alias="deviceIdentityVerified",
    )
    emulator_identity_verified: Literal[False] = Field(
        default=False,
        alias="emulatorIdentityVerified",
    )
    app_installed: Literal[False] = Field(default=False, alias="appInstalled")
    vulnerability_confirmed: Literal[False] = Field(
        default=False,
        alias="vulnerabilityConfirmed",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")

    @field_validator(
        "typed_surface_only",
        "discovery_observed",
        "package_resolved",
        "package_bytes_verified",
        "package_format_verified",
        "manifest_verified",
        "application_identity_verified",
        "signing_identity_verified",
        "runtime_declaration_verified",
        "storage_declaration_verified",
        "deep_link_declaration_verified",
        "tls_policy_verified",
        "authentication_flow_verified",
        "device_identity_verified",
        "emulator_identity_verified",
        "app_installed",
        "vulnerability_confirmed",
        "evidence_sealed",
        "graph_admitted",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Mobile Surface state markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_mobile_application_runtime_locator_registry()
        _require_known_instance_fields(
            self.locator_registry,
            label="Mobile locator registry reference",
        )
        canonical_locator = _validated_mobile_locator(self.locator)
        registered = next(
            (item for item in registry.locators if item.locator_kind == canonical_locator.kind),
            None,
        )
        if (
            canonical_locator != self.locator
            or self.domain_classification != _mobile_domain_classification()
            or self.domain_graph_type_set != _mobile_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed Mobile application/runtime Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Mobile application/runtime Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest(
            "pajin.discovery.mobile-application-runtime-surface/v1",
            material,
        )
        surface_id: _SurfaceId = f"mobile-application-runtime-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Mobile Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Mobile Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> MobileApplicationRuntimeSurfaceRef:
        """Return a content-addressed inert Mobile Surface reference."""

        canonical = _validated_mobile_surface(self)
        return MobileApplicationRuntimeSurfaceRef(
            surfaceId=canonical.surface_id,
            surfaceDigest=canonical.surface_digest,
            surfaceType=canonical.surface_type,
            locatorSchema=canonical.locator_schema,
            surfaceClass=canonical.surface_class,
            locatorKind=canonical.locator.kind,
            locatorRegistry=canonical.locator_registry,
        )


def registered_mobile_application_runtime_locator_registry() -> (
    MobileApplicationRuntimeLocatorRegistry
):
    """Return the MOBILE-001A registry without package-analysis or device authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return MobileApplicationRuntimeLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_mobile_domain_classification(),
        domainGraphTypeSet=_mobile_graph_type_set(),
        locators=_registered_mobile_locators(),
    )


@cache
def _mobile_locator_registry_identity() -> tuple[str, str, str]:
    registry = registered_mobile_application_runtime_locator_registry()
    return registry.registry_id, registry.registry_version, registry.registry_digest


def resolve_registered_mobile_application_runtime_locator(
    reference: MobileApplicationRuntimeLocatorRef,
) -> RegisteredMobileApplicationRuntimeLocator:
    """Resolve one exact Mobile locator without transferring authority."""

    try:
        _require_known_instance_fields(reference, label="Mobile locator reference")
        canonical_reference = MobileApplicationRuntimeLocatorRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise MobileSurfaceRegistryError(
            "Mobile application/runtime locator is not registered exactly"
        ) from exc
    if canonical_reference != reference:
        raise MobileSurfaceRegistryError(
            "Mobile application/runtime locator is not registered exactly"
        )
    for locator in registered_mobile_application_runtime_locator_registry().locators:
        if locator.reference() == canonical_reference:
            return locator.model_copy(deep=True)
    raise MobileSurfaceRegistryError("Mobile application/runtime locator is not registered exactly")


def resolve_mobile_application_runtime_locator_registry(
    reference: MobileApplicationRuntimeLocatorRegistryRef,
) -> MobileApplicationRuntimeLocatorRegistry:
    """Resolve the complete Mobile registry without activating analysis behavior."""

    try:
        _require_known_instance_fields(reference, label="Mobile locator registry reference")
        canonical_reference = MobileApplicationRuntimeLocatorRegistryRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise MobileSurfaceRegistryError(
            "Mobile application/runtime locator registry is not registered exactly"
        ) from exc
    if canonical_reference != reference:
        raise MobileSurfaceRegistryError(
            "Mobile application/runtime locator registry is not registered exactly"
        )
    registry = registered_mobile_application_runtime_locator_registry()
    if registry.reference() == canonical_reference:
        return registry.model_copy(deep=True)
    raise MobileSurfaceRegistryError(
        "Mobile application/runtime locator registry is not registered exactly"
    )


def typed_mobile_application_runtime_surface(
    *,
    locator: MobileApplicationRuntimeSurfaceLocator,
) -> MobileApplicationRuntimeSurface:
    """Type a revalidated locator as inert registered-not-authorized Mobile knowledge."""

    canonical_locator = _validated_mobile_locator(locator)
    registry = registered_mobile_application_runtime_locator_registry()
    registered = next(
        item for item in registry.locators if item.locator_kind == canonical_locator.kind
    )
    return MobileApplicationRuntimeSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_mobile_domain_classification(),
        domainGraphTypeSet=_mobile_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=canonical_locator,
    )


def mobile_apk_surface_locator(*, artifact_sha256: str) -> MobileAPKSurfaceLocator:
    """Build one APK declaration without reading bytes or verifying package format."""

    return MobileAPKSurfaceLocator(
        applicationArtifact=application_binary_surface_locator(artifact_sha256=artifact_sha256)
    )


def mobile_ipa_surface_locator(*, artifact_sha256: str) -> MobileIPASurfaceLocator:
    """Build one IPA declaration without reading bytes or verifying package format."""

    return MobileIPASurfaceLocator(
        applicationArtifact=application_binary_surface_locator(artifact_sha256=artifact_sha256)
    )


def mobile_application_surface_locator(
    *,
    parent: MobilePackageSurfaceLocator,
    application_id: str,
) -> MobileApplicationSurfaceLocator:
    """Build one exact application ID below a revalidated package lineage."""

    return MobileApplicationSurfaceLocator(
        parent=_validated_mobile_package(parent),
        applicationId=application_id,
    )


def mobile_runtime_surface_locator(
    *,
    parent: MobileApplicationSurfaceLocator,
    runtime_family: MobilePlatform,
    declaration_kind: MobileRuntimeDeclarationKind,
    runtime_version: str,
) -> MobileRuntimeSurfaceLocator:
    """Build one declared runtime requirement without live device state."""

    return MobileRuntimeSurfaceLocator(
        parent=_validated_mobile_application(parent),
        runtimeFamily=runtime_family,
        declarationKind=declaration_kind,
        runtimeVersion=runtime_version,
    )


def mobile_storage_surface_locator(
    *,
    parent: MobileApplicationSurfaceLocator,
    storage_kind: MobileStorageKind,
    storage_id: str,
    declaration_sha256: str,
) -> MobileStorageSurfaceLocator:
    """Build one logical storage declaration without a device path or stored value."""

    return MobileStorageSurfaceLocator(
        parent=_validated_mobile_application(parent),
        storageKind=storage_kind,
        storageId=storage_id,
        declarationSha256=declaration_sha256,
    )


def mobile_deep_link_surface_locator(
    *,
    parent: MobileApplicationSurfaceLocator,
    link_kind: MobileDeepLinkKind,
    scheme: str,
    route_id: str,
    declaration_sha256: str,
    host: str | None = None,
    port: int | None = None,
) -> MobileDeepLinkSurfaceLocator:
    """Build one sanitized link declaration without a full URI or route value."""

    return MobileDeepLinkSurfaceLocator(
        parent=_validated_mobile_application(parent),
        linkKind=link_kind,
        scheme=scheme,
        host=host,
        port=port,
        routeId=route_id,
        declarationSha256=declaration_sha256,
    )


def mobile_tls_policy_surface_locator(
    *,
    parent: MobileApplicationSurfaceLocator,
    policy_kind: MobileTLSPolicyKind,
    policy_id: str,
    declaration_sha256: str,
) -> MobileTLSPolicySurfaceLocator:
    """Build one sanitized TLS-policy declaration without certificate or key material."""

    return MobileTLSPolicySurfaceLocator(
        parent=_validated_mobile_application(parent),
        policyKind=policy_kind,
        policyId=policy_id,
        declarationSha256=declaration_sha256,
    )


def mobile_authentication_surface_locator(
    *,
    parent: MobileApplicationSurfaceLocator,
    authentication_kind: MobileAuthenticationKind,
    flow_id: str,
    declaration_sha256: str,
) -> MobileAuthenticationSurfaceLocator:
    """Build one sanitized authentication-flow declaration without credentials."""

    return MobileAuthenticationSurfaceLocator(
        parent=_validated_mobile_application(parent),
        authenticationKind=authentication_kind,
        flowId=flow_id,
        declarationSha256=declaration_sha256,
    )


@cache
def _registered_mobile_locators() -> tuple[RegisteredMobileApplicationRuntimeLocator, ...]:
    return tuple(
        RegisteredMobileApplicationRuntimeLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_mobile_domain_classification(),
            domainGraphTypeSet=_mobile_graph_type_set(),
            parentRequirement=spec.parent_requirement,
            platformRequirement=spec.platform_requirement,
            declarationDigestRequired=spec.declaration_digest_required,
            exactVersionRequired=spec.exact_version_required,
        )
        for spec in _MOBILE_LOCATOR_SPECS
    )


@cache
def _mobile_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.MOBILE
    )


@cache
def _mobile_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.MOBILE
    )


def _require_exact_application_binary(locator: ApplicationBinarySurfaceLocator) -> None:
    _require_known_instance_fields(locator, label="Application binary locator")
    canonical = ApplicationBinarySurfaceLocator.model_validate(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Mobile package Application artifact parent is not exact")


def _validated_mobile_package(
    locator: MobilePackageSurfaceLocator,
) -> MobileAPKSurfaceLocator | MobileIPASurfaceLocator:
    _require_known_instance_fields(locator, label="Mobile package locator")
    _require_exact_application_binary(locator.application_artifact)
    canonical = _MOBILE_PACKAGE_ADAPTER.validate_python(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Mobile package locator instance is not exact")
    return canonical


def _validated_mobile_application(
    locator: MobileApplicationSurfaceLocator,
) -> MobileApplicationSurfaceLocator:
    _require_known_instance_fields(locator, label="Mobile application locator")
    _validated_mobile_package(locator.parent)
    canonical = MobileApplicationSurfaceLocator.model_validate(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Mobile application locator instance is not exact")
    return canonical


def _validated_mobile_locator(
    locator: MobileApplicationRuntimeSurfaceLocator,
) -> (
    MobileAPKSurfaceLocator
    | MobileIPASurfaceLocator
    | MobileApplicationSurfaceLocator
    | MobileRuntimeSurfaceLocator
    | MobileStorageSurfaceLocator
    | MobileDeepLinkSurfaceLocator
    | MobileTLSPolicySurfaceLocator
    | MobileAuthenticationSurfaceLocator
):
    _require_known_instance_fields(locator, label="Mobile application/runtime locator")
    if isinstance(locator, MobileAPKSurfaceLocator | MobileIPASurfaceLocator):
        _require_exact_application_binary(locator.application_artifact)
    elif isinstance(locator, MobileApplicationSurfaceLocator):
        _validated_mobile_package(locator.parent)
    else:
        _validated_mobile_application(locator.parent)
    canonical = _MOBILE_LOCATOR_ADAPTER.validate_python(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Mobile application/runtime locator instance is not exact")
    return canonical


def _require_known_instance_fields(model: StrictModel, *, label: str) -> None:
    unexpected = set(model.__dict__) - set(type(model).model_fields)
    if unexpected:
        raise ValueError(f"{label} contains unmodeled instance state")
    for field_name in type(model).model_fields:
        _require_known_instance_value(
            getattr(model, field_name),
            label=f"{label}.{field_name}",
        )


def _require_known_instance_value(value: object, *, label: str) -> None:
    if isinstance(value, StrictModel):
        _require_known_instance_fields(value, label=label)
    elif isinstance(value, tuple | list):
        for index, item in enumerate(value):
            _require_known_instance_value(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_known_instance_value(item, label=f"{label}[{key!r}]")


def _validated_registered_mobile_locator(
    locator: RegisteredMobileApplicationRuntimeLocator,
) -> RegisteredMobileApplicationRuntimeLocator:
    _require_known_instance_fields(locator, label="Registered Mobile locator")
    canonical = RegisteredMobileApplicationRuntimeLocator.model_validate(
        locator.model_dump(mode="json", by_alias=True)
    )
    if canonical != locator:
        raise ValueError("Registered Mobile locator instance is not exact")
    return canonical


def _validated_mobile_locator_registry(
    registry: MobileApplicationRuntimeLocatorRegistry,
) -> MobileApplicationRuntimeLocatorRegistry:
    _require_known_instance_fields(registry, label="Mobile locator registry")
    canonical = MobileApplicationRuntimeLocatorRegistry.model_validate(
        registry.model_dump(mode="json", by_alias=True)
    )
    if canonical != registry:
        raise ValueError("Mobile locator registry instance is not exact")
    return canonical


def _validated_mobile_surface(
    surface: MobileApplicationRuntimeSurface,
) -> MobileApplicationRuntimeSurface:
    _require_known_instance_fields(surface, label="Typed Mobile Surface")
    canonical = MobileApplicationRuntimeSurface.model_validate(
        surface.model_dump(mode="json", by_alias=True)
    )
    if canonical != surface:
        raise ValueError("Typed Mobile Surface instance is not exact")
    return canonical


def _mobile_package_platform(locator: MobilePackageSurfaceLocator) -> MobilePlatform:
    if isinstance(locator, MobileAPKSurfaceLocator):
        return MobilePlatform.ANDROID
    return MobilePlatform.IOS


def _mobile_application_platform(locator: MobileApplicationSurfaceLocator) -> MobilePlatform:
    return _mobile_package_platform(locator.parent)


def _canonical_mobile_coordinate(value: object, *, label: str) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    if "://" in value or any(character in value for character in "/\\?#*@:%"):
        raise ValueError(f"{label} cannot contain path, URL, authority, or wildcard syntax")
    canonical = value.casefold()
    tokens = tuple(filter(None, re.split(r"[._+-]", canonical)))
    if not tokens or any(token in _MUTABLE_COORDINATE_TOKENS for token in tokens):
        raise ValueError(f"{label} must be one explicit stable coordinate")
    return canonical


def _canonical_exact_runtime_version(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("Mobile runtime version cannot contain surrounding or control whitespace")
    canonical = value.casefold()
    tokens = tuple(filter(None, re.split(r"[._+-]", canonical)))
    if not tokens or any(token in _MUTABLE_COORDINATE_TOKENS for token in tokens):
        raise ValueError("Mobile runtime version must be one exact non-floating version")
    return canonical


def _canonical_mobile_scheme(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("Mobile deep-link scheme cannot contain whitespace")
    if ":" in value or any(character in value for character in "/\\?#*@%"):
        raise ValueError("Mobile deep-link scheme must not contain URI data")
    return value.casefold()


def _canonical_mobile_host(value: object) -> object:
    if value is None or not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("Mobile deep-link host cannot contain whitespace")
    if value.endswith(".") or any(character in value for character in "/\\?#*:@%"):
        raise ValueError("Mobile deep-link host must be one exact DNS name")
    try:
        canonical = idna.encode(
            value,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii")
        decoded = idna.decode(
            canonical.encode("ascii"),
            uts46=True,
            std3_rules=True,
        )
        round_trip = idna.encode(
            decoded,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError("Mobile deep-link host is not valid IDNA") from exc
    if round_trip != canonical:
        raise ValueError("Mobile deep-link host is not stable IDNA")
    labels = canonical.split(".")
    if len(canonical) > 253 or any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError("Mobile deep-link host is not one canonical DNS name")
    return canonical


__all__ = [
    "MOBILE_APPLICATION_RUNTIME_LOCATOR_API_VERSION",
    "MOBILE_APPLICATION_RUNTIME_LOCATOR_REGISTRY_API_VERSION",
    "MOBILE_APPLICATION_RUNTIME_LOCATOR_SCHEMA",
    "MOBILE_APPLICATION_RUNTIME_SURFACE_API_VERSION",
    "MOBILE_APPLICATION_RUNTIME_SURFACE_TYPE",
    "MobileAPKSurfaceLocator",
    "MobileApplicationRuntimeLocatorRef",
    "MobileApplicationRuntimeLocatorRegistry",
    "MobileApplicationRuntimeLocatorRegistryRef",
    "MobileApplicationRuntimeSurface",
    "MobileApplicationRuntimeSurfaceLocator",
    "MobileApplicationRuntimeSurfaceRef",
    "MobileApplicationSurfaceLocator",
    "MobileAuthenticationKind",
    "MobileAuthenticationSurfaceLocator",
    "MobileDeepLinkKind",
    "MobileDeepLinkSurfaceLocator",
    "MobileIPASurfaceLocator",
    "MobilePackageSurfaceLocator",
    "MobileParentRequirement",
    "MobilePlatform",
    "MobilePlatformRequirement",
    "MobileRuntimeDeclarationKind",
    "MobileRuntimeSurfaceLocator",
    "MobileStorageKind",
    "MobileStorageSurfaceLocator",
    "MobileSurfaceClass",
    "MobileSurfaceLocatorKind",
    "MobileSurfaceRegistryError",
    "MobileTLSPolicyKind",
    "MobileTLSPolicySurfaceLocator",
    "RegisteredMobileApplicationRuntimeLocator",
    "mobile_apk_surface_locator",
    "mobile_application_surface_locator",
    "mobile_authentication_surface_locator",
    "mobile_deep_link_surface_locator",
    "mobile_ipa_surface_locator",
    "mobile_runtime_surface_locator",
    "mobile_storage_surface_locator",
    "mobile_tls_policy_surface_locator",
    "registered_mobile_application_runtime_locator_registry",
    "resolve_mobile_application_runtime_locator_registry",
    "resolve_registered_mobile_application_runtime_locator",
    "typed_mobile_application_runtime_surface",
]
