"""NET-002A exact measured Network case selection without runtime authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkMetricApplicability,
    DomainBenchmarkMetricRef,
    DomainBenchmarkNotApplicableReason,
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    RegisteredDomainBenchmarkPlan,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_metric,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import BenchmarkMetricUnit, benchmark_digest
from pajin.capabilities.network_service import (
    NetworkServiceIdentificationBindingRef,
    NetworkServiceProtocolBudget,
    registered_network_service_identification_binding,
)
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.workflow.network_replay_benchmark import (
    NetworkBenchmarkGroundTruthClass,
    NetworkServiceBenchmarkFixtureCase,
    registered_network_service_benchmark_fixture_profile,
)

NETWORK_MEASURED_CASE_REGISTRY_API_VERSION: Literal[
    "pajin.dev/network-measured-case-registry/v1alpha1"
] = "pajin.dev/network-measured-case-registry/v1alpha1"
NETWORK_PRIVATE_GROUND_TRUTH_BINDING_API_VERSION: Literal[
    "pajin.dev/network-private-ground-truth-binding/v1alpha1"
] = "pajin.dev/network-private-ground-truth-binding/v1alpha1"
NETWORK_TCP_BANNER_EMITTER_PROFILE_API_VERSION: Literal[
    "pajin.dev/network-tcp-banner-emitter-profile/v1alpha1"
] = "pajin.dev/network-tcp-banner-emitter-profile/v1alpha1"
NETWORK_IMAGE_IDENTITY_PROFILE_API_VERSION: Literal[
    "pajin.dev/network-image-identity-profile/v1alpha1"
] = "pajin.dev/network-image-identity-profile/v1alpha1"
NETWORK_MEASUREMENT_PROTOCOL_API_VERSION: Literal[
    "pajin.dev/network-measurement-protocol/v1alpha1"
] = "pajin.dev/network-measurement-protocol/v1alpha1"
NETWORK_VALIDATION_FLOOR_POLICY_API_VERSION: Literal[
    "pajin.dev/network-validation-floor-policy/v1alpha1"
] = "pajin.dev/network-validation-floor-policy/v1alpha1"
NETWORK_MEASURED_CASE_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/network-measured-case-authority/v1alpha1"
] = "pajin.dev/network-measured-case-authority/v1alpha1"

NETWORK_TCP_BANNER_EMITTER_PORT = 18_080
_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]

_REGISTRY_FALSE_FIELDS = (
    "target_selected",
    "target_factory_authorized",
    "measurement_observed",
    "service_confirmation_authorized",
    "execution_authorized",
)
_PRIVATE_FALSE_FIELDS = (
    "public_disclosure_authorized",
    "measurement_observed",
    "service_confirmation_authorized",
    "execution_authorized",
)
_EMITTER_FALSE_FIELDS = (
    "docker_image_built",
    "target_created",
    "listener_started",
    "caller_banner_authorized",
    "caller_command_authorized",
    "caller_port_authorized",
    "application_payload_read_authorized",
    "execution_authorized",
)
_IMAGE_FALSE_FIELDS = (
    "docker_image_built",
    "observed_image_id_bound",
    "caller_selected_image_authorized",
    "runtime_use_authorized",
)
_PROTOCOL_FALSE_FIELDS = (
    "target_created",
    "network_created",
    "provider_selected",
    "capability_activation_authorized",
    "approval_satisfied",
    "permit_issuance_authorized",
    "gateway_execution_authorized",
    "worker_execution_authorized",
    "live_measurement_authorized",
    "dns_authorized",
    "udp_authorized",
    "port_range_authorized",
    "port_enumeration_authorized",
    "raw_socket_authorized",
    "application_protocol_write_authorized",
    "credential_access_authorized",
    "external_target_authorized",
    "production_target_authorized",
    "general_scanner_authorized",
    "execution_authorized",
)
_FLOOR_FALSE_FIELDS = (
    "measurement_evaluation_authorized",
    "validation_floor_satisfied",
    "service_confirmation_authorized",
    "finding_authority",
    "graph_mutation_authorized",
    "product_projection_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "execution_authorized",
)
_AUTHORITY_FALSE_FIELDS = (
    "docker_image_build_authorized",
    "target_selection_authorized",
    "target_creation_authorized",
    "network_creation_authorized",
    "provider_selection_authorized",
    "capability_activation_authorized",
    "approval_satisfied",
    "permit_issuance_authorized",
    "gateway_execution_authorized",
    "worker_execution_authorized",
    "live_measurement_authorized",
    "measurement_observed",
    "validation_floor_satisfied",
    "product_projection_authorized",
    "graph_mutation_authorized",
    "finding_authority",
    "reporting_authorized",
    "external_delivery_authorized",
    "dns_authorized",
    "udp_authorized",
    "port_range_authorized",
    "port_enumeration_authorized",
    "raw_socket_authorized",
    "application_protocol_write_authorized",
    "credential_access_authorized",
    "external_target_authorized",
    "production_target_authorized",
    "service_confirmation_authorized",
    "general_scanner_authorized",
    "caller_configuration_authorized",
    "execution_authorized",
)


class NetworkMeasuredCaseAuthorityError(RuntimeError):
    """Raised when one NET-002A registration or private binding drifts."""


class NetworkExpectedClassifierOutcome(StrEnum):
    """Private expected outcomes; a Control is unresolved, not a service label."""

    EXACT_SERVICE_LABEL = "exact-service-label"
    PROTOCOL_LABEL_UNRESOLVED = "protocol-label-unresolved"


class NetworkMeasurementImageRole(StrEnum):
    """Canonical NET-002 image-role order is Target, Worker, then proxy."""

    TARGET = "target"
    WORKER = "worker"
    PROXY = "proxy"


class NetworkMetricFloorComparison(StrEnum):
    """Registered comparison semantics; no value has been measured in NET-002A."""

    AT_LEAST = "at-least"
    AT_MOST = "at-most"
    MEASUREMENT_REQUIRED = "measurement-required"
    NOT_APPLICABLE = "not-applicable"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class NetworkMeasuredCaseRef(_FrozenStrictModel):
    """Public-safe case identity and commitment to its private Ground Truth."""

    case_id: _Identifier = Field(alias="caseId")
    case_digest: _Sha256 = Field(alias="caseDigest")
    private_ground_truth_case_digest: _Sha256 = Field(alias="privateGroundTruthCaseDigest")


class NetworkMeasuredCaseRegistration(_FrozenStrictModel):
    """One public case registration without banner bytes or an expected label field."""

    case_id: _Identifier = Field(alias="caseId")
    case_digest: str = Field(default="", alias="caseDigest", max_length=64)
    ground_truth_class: NetworkBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    protocol_profile: Literal["tcp-passive-banner-v1"] = Field(
        default="tcp-passive-banner-v1",
        alias="protocolProfile",
    )
    private_ground_truth_case_digest: _Sha256 = Field(alias="privateGroundTruthCaseDigest")
    measurement_role: Literal["classifier-positive", "classifier-negative-control"] = Field(
        alias="measurementRole"
    )
    state: Literal["registered-public-case-not-measured"] = "registered-public-case-not-measured"

    @model_validator(mode="after")
    def bind_case_identity(self) -> Self:
        expected_role = (
            "classifier-positive"
            if self.ground_truth_class is NetworkBenchmarkGroundTruthClass.KNOWN_POSITIVE
            else "classifier-negative-control"
        )
        if self.measurement_role != expected_role:
            raise ValueError("NET-002A public case role differs from Ground Truth class")
        material = self.model_dump(mode="json", by_alias=True, exclude={"case_digest"})
        digest = benchmark_digest(
            "pajin.workflow.network-measured-public-case/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.case_digest and self.case_digest != digest:
            raise ValueError("NET-002A public case Digest differs")
        object.__setattr__(self, "case_digest", digest)
        return self

    def reference(self) -> NetworkMeasuredCaseRef:
        return NetworkMeasuredCaseRef(
            caseId=self.case_id,
            caseDigest=self.case_digest,
            privateGroundTruthCaseDigest=self.private_ground_truth_case_digest,
        )


class NetworkMeasuredCaseRegistryRef(_FrozenStrictModel):
    """Exact content-addressed lookup for the six public cases."""

    registry_id: str = Field(
        alias="registryId",
        pattern=r"^network-measured-case-registry_[a-f0-9]{64}$",
    )
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class NetworkMeasuredCaseRegistry(_FrozenStrictModel):
    """Network-specific public registration; it is not the generic Finding catalog."""

    api_version: Literal["pajin.dev/network-measured-case-registry/v1alpha1"] = Field(
        default=NETWORK_MEASURED_CASE_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkMeasuredCaseRegistry"] = "NetworkMeasuredCaseRegistry"
    registry_id: str = Field(default="", alias="registryId", max_length=120)
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    cases: tuple[NetworkMeasuredCaseRegistration, ...] = Field(min_length=6, max_length=6)
    known_positive_count: Literal[5] = Field(default=5, alias="knownPositiveCount")
    negative_control_count: Literal[1] = Field(default=1, alias="negativeControlCount")
    state: Literal["registered-public-membership-not-measured"] = (
        "registered-public-membership-not-measured"
    )
    target_selected: Literal[False] = Field(default=False, alias="targetSelected")
    target_factory_authorized: Literal[False] = Field(
        default=False, alias="targetFactoryAuthorized"
    )
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    service_confirmation_authorized: Literal[False] = Field(
        default=False, alias="serviceConfirmationAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("known_positive_count", "negative_control_count", mode="before")
    @classmethod
    def require_exact_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("NET-002A public case counts must be exact integers")
        return value

    @field_validator(*_REGISTRY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A public registry authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_registry_identity(self) -> Self:
        if self.cases != _registered_public_cases():
            raise ValueError("NET-002A public six-case membership or order differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_id", "registry_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-measured-case-registry/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        registry_id = f"network-measured-case-registry_{digest}"
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("NET-002A public registry Digest differs")
        if self.registry_id and self.registry_id != registry_id:
            raise ValueError("NET-002A public registry ID differs")
        object.__setattr__(self, "registry_digest", digest)
        object.__setattr__(self, "registry_id", registry_id)
        return self

    def reference(self) -> NetworkMeasuredCaseRegistryRef:
        return NetworkMeasuredCaseRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class NetworkPrivateGroundTruthCase(_FrozenStrictModel):
    """Deployment-private NET-001D case, including banner and expected outcome."""

    case_id: _Identifier = Field(alias="caseId")
    case_digest: str = Field(default="", alias="caseDigest", max_length=64)
    fixture: NetworkServiceBenchmarkFixtureCase
    expected_classifier_outcome: NetworkExpectedClassifierOutcome = Field(
        alias="expectedClassifierOutcome"
    )

    @model_validator(mode="after")
    def bind_private_case(self) -> Self:
        expected_outcome = (
            NetworkExpectedClassifierOutcome.EXACT_SERVICE_LABEL
            if self.fixture.expected_service_name is not None
            else NetworkExpectedClassifierOutcome.PROTOCOL_LABEL_UNRESOLVED
        )
        if (
            self.case_id != self.fixture.fixture_id
            or self.expected_classifier_outcome is not expected_outcome
        ):
            raise ValueError("NET-002A private Ground Truth case differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"case_digest"})
        digest = benchmark_digest(
            "pajin.workflow.network-private-ground-truth-case/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.case_digest and self.case_digest != digest:
            raise ValueError("NET-002A private Ground Truth case Digest differs")
        object.__setattr__(self, "case_digest", digest)
        return self


class NetworkPrivateGroundTruthBinding(_FrozenStrictModel):
    """Separate private binding to the unchanged exact NET-001D fixture profile."""

    api_version: Literal["pajin.dev/network-private-ground-truth-binding/v1alpha1"] = Field(
        default=NETWORK_PRIVATE_GROUND_TRUTH_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkPrivateGroundTruthBinding"] = "NetworkPrivateGroundTruthBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=120)
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    public_registry: NetworkMeasuredCaseRegistryRef = Field(alias="publicRegistry")
    net001d_profile_id: _Identifier = Field(alias="net001dProfileId")
    net001d_profile_digest: _Sha256 = Field(alias="net001dProfileDigest")
    cases: tuple[NetworkPrivateGroundTruthCase, ...] = Field(min_length=6, max_length=6)
    visibility: Literal["deployment-private"] = "deployment-private"
    state: Literal["registered-private-ground-truth-not-observed"] = (
        "registered-private-ground-truth-not-observed"
    )
    public_disclosure_authorized: Literal[False] = Field(
        default=False, alias="publicDisclosureAuthorized"
    )
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    service_confirmation_authorized: Literal[False] = Field(
        default=False, alias="serviceConfirmationAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_PRIVATE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A private Ground Truth markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_private_identity(self) -> Self:
        profile = registered_network_service_benchmark_fixture_profile()
        if (
            self.public_registry != registered_network_measured_case_registry().reference()
            or self.net001d_profile_id != profile.profile_id
            or self.net001d_profile_digest != profile.profile_digest
            or self.cases != _registered_private_cases()
        ):
            raise ValueError("NET-002A private Ground Truth binding differs from NET-001D")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-private-ground-truth-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"network-private-ground-truth_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("NET-002A private Ground Truth binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("NET-002A private Ground Truth binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


class NetworkTCPBannerEmitterProfileRef(_FrozenStrictModel):
    """Exact fixed-case emitter profile lookup, not a running Target."""

    profile_id: str = Field(
        alias="profileId",
        pattern=r"^network-tcp-banner-emitter_[a-f0-9]{64}$",
    )
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")


class NetworkTCPBannerEmitterProfile(_FrozenStrictModel):
    """Code-owned case-ID-only TCP emitter profile with no socket authority."""

    api_version: Literal["pajin.dev/network-tcp-banner-emitter-profile/v1alpha1"] = Field(
        default=NETWORK_TCP_BANNER_EMITTER_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkTCPBannerEmitterProfile"] = "NetworkTCPBannerEmitterProfile"
    profile_id: str = Field(default="", alias="profileId", max_length=120)
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    public_registry: NetworkMeasuredCaseRegistryRef = Field(alias="publicRegistry")
    cases: tuple[NetworkMeasuredCaseRef, ...] = Field(min_length=6, max_length=6)
    fixed_container_port: Literal[18080] = Field(
        default=18_080,
        alias="fixedContainerPort",
    )
    accepted_configuration: Literal["one-code-owned-case-id"] = Field(
        default="one-code-owned-case-id",
        alias="acceptedConfiguration",
    )
    connection_behavior: Literal["send-case-banner-immediately-then-close"] = Field(
        default="send-case-banner-immediately-then-close",
        alias="connectionBehavior",
    )
    target_application_read_bytes: Literal[0] = Field(
        default=0,
        alias="targetApplicationReadBytes",
    )
    worker_application_write_bytes: Literal[0] = Field(
        default=0,
        alias="workerApplicationWriteBytes",
    )
    state: Literal["registered-profile-image-not-built"] = "registered-profile-image-not-built"
    docker_image_built: Literal[False] = Field(default=False, alias="dockerImageBuilt")
    target_created: Literal[False] = Field(default=False, alias="targetCreated")
    listener_started: Literal[False] = Field(default=False, alias="listenerStarted")
    caller_banner_authorized: Literal[False] = Field(default=False, alias="callerBannerAuthorized")
    caller_command_authorized: Literal[False] = Field(
        default=False, alias="callerCommandAuthorized"
    )
    caller_port_authorized: Literal[False] = Field(default=False, alias="callerPortAuthorized")
    application_payload_read_authorized: Literal[False] = Field(
        default=False, alias="applicationPayloadReadAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "fixed_container_port",
        "target_application_read_bytes",
        "worker_application_write_bytes",
        mode="before",
    )
    @classmethod
    def require_exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("NET-002A emitter values must be exact integers")
        return value

    @field_validator(*_EMITTER_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A emitter authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_emitter_identity(self) -> Self:
        registry = registered_network_measured_case_registry()
        if self.public_registry != registry.reference() or self.cases != tuple(
            case.reference() for case in registry.cases
        ):
            raise ValueError("NET-002A fixed-case emitter profile differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-tcp-banner-emitter-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"network-tcp-banner-emitter_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("NET-002A emitter profile Digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("NET-002A emitter profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self

    def reference(self) -> NetworkTCPBannerEmitterProfileRef:
        return NetworkTCPBannerEmitterProfileRef(
            profileId=self.profile_id,
            profileVersion=self.profile_version,
            profileDigest=self.profile_digest,
        )


class NetworkImageContractIdentity(_FrozenStrictModel):
    """Immutable image contract; an observed OCI image ID remains required in NET-002B."""

    identity_id: str = Field(
        default="",
        alias="identityId",
        max_length=120,
    )
    identity_version: Literal["1.0.0"] = Field(default="1.0.0", alias="identityVersion")
    identity_digest: str = Field(default="", alias="identityDigest", max_length=64)
    role: NetworkMeasurementImageRole
    component_id: _Identifier = Field(alias="componentId")
    contract_digest: _Sha256 = Field(alias="contractDigest")
    immutable_observed_image_id_required: Literal[True] = Field(
        default=True,
        alias="immutableObservedImageIdRequired",
    )
    docker_image_built: Literal[False] = Field(default=False, alias="dockerImageBuilt")
    observed_image_id_bound: Literal[False] = Field(default=False, alias="observedImageIdBound")
    caller_selected_image_authorized: Literal[False] = Field(
        default=False, alias="callerSelectedImageAuthorized"
    )
    runtime_use_authorized: Literal[False] = Field(default=False, alias="runtimeUseAuthorized")

    @field_validator("immutable_observed_image_id_required", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002A immutable observed image requirement must be true")
        return value

    @field_validator(*_IMAGE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A image authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_image_contract_identity(self) -> Self:
        component_id, contract_digest = _image_contract(self.role)
        if self.component_id != component_id or self.contract_digest != contract_digest:
            raise ValueError("NET-002A image role contract differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"identity_id", "identity_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-image-contract-identity/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        identity_id = f"network-image-contract_{digest}"
        if self.identity_digest and self.identity_digest != digest:
            raise ValueError("NET-002A image contract Digest differs")
        if self.identity_id and self.identity_id != identity_id:
            raise ValueError("NET-002A image contract ID differs")
        object.__setattr__(self, "identity_digest", digest)
        object.__setattr__(self, "identity_id", identity_id)
        return self


class NetworkImageIdentityProfileRef(_FrozenStrictModel):
    """Exact Target/Worker/proxy image-contract profile lookup."""

    profile_id: str = Field(
        alias="profileId",
        pattern=r"^network-image-identity-profile_[a-f0-9]{64}$",
    )
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")


class NetworkImageIdentityProfile(_FrozenStrictModel):
    """Canonical Target/Worker/proxy contracts without fabricated Docker identities."""

    api_version: Literal["pajin.dev/network-image-identity-profile/v1alpha1"] = Field(
        default=NETWORK_IMAGE_IDENTITY_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkImageIdentityProfile"] = "NetworkImageIdentityProfile"
    profile_id: str = Field(default="", alias="profileId", max_length=128)
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    roles: tuple[NetworkImageContractIdentity, ...] = Field(min_length=3, max_length=3)
    state: Literal["registered-image-contracts-no-images-observed"] = (
        "registered-image-contracts-no-images-observed"
    )
    runtime_binding_requires_exact_observed_image_ids: Literal[True] = Field(
        default=True,
        alias="runtimeBindingRequiresExactObservedImageIds",
    )
    runtime_use_authorized: Literal[False] = Field(default=False, alias="runtimeUseAuthorized")

    @field_validator("runtime_binding_requires_exact_observed_image_ids", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002A runtime image binding requirement must be true")
        return value

    @field_validator("runtime_use_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A image profile runtime authority must be false")
        return value

    @model_validator(mode="after")
    def bind_profile_identity(self) -> Self:
        if self.roles != _registered_image_contracts():
            raise ValueError("NET-002A Target/Worker/proxy image contract order differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-image-identity-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"network-image-identity-profile_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("NET-002A image identity profile Digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("NET-002A image identity profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self

    def reference(self) -> NetworkImageIdentityProfileRef:
        return NetworkImageIdentityProfileRef(
            profileId=self.profile_id,
            profileVersion=self.profile_version,
            profileDigest=self.profile_digest,
        )


class NetworkMeasurementProtocolRef(_FrozenStrictModel):
    """Exact content-addressed source/Replay protocol lookup."""

    protocol_id: str = Field(
        alias="protocolId",
        pattern=r"^network-measurement-protocol_[a-f0-9]{64}$",
    )
    protocol_version: Literal["1.0.0"] = Field(alias="protocolVersion")
    protocol_digest: _Sha256 = Field(alias="protocolDigest")


class NetworkMeasurementProtocol(_FrozenStrictModel):
    """Six source plus six Replay requirements; no execution has been selected."""

    api_version: Literal["pajin.dev/network-measurement-protocol/v1alpha1"] = Field(
        default=NETWORK_MEASUREMENT_PROTOCOL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkMeasurementProtocol"] = "NetworkMeasurementProtocol"
    protocol_id: str = Field(default="", alias="protocolId", max_length=130)
    protocol_version: Literal["1.0.0"] = Field(default="1.0.0", alias="protocolVersion")
    protocol_digest: str = Field(default="", alias="protocolDigest", max_length=64)
    public_registry: NetworkMeasuredCaseRegistryRef = Field(alias="publicRegistry")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    emitter_profile: NetworkTCPBannerEmitterProfileRef = Field(alias="emitterProfile")
    image_identity_profile: NetworkImageIdentityProfileRef = Field(alias="imageIdentityProfile")
    network_service_binding: NetworkServiceIdentificationBindingRef = Field(
        alias="networkServiceBinding"
    )
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    protocol_budget: NetworkServiceProtocolBudget = Field(alias="protocolBudget")
    source_case_order: tuple[NetworkMeasuredCaseRef, ...] = Field(
        alias="sourceCaseOrder",
        min_length=6,
        max_length=6,
    )
    replay_case_order: tuple[NetworkMeasuredCaseRef, ...] = Field(
        alias="replayCaseOrder",
        min_length=6,
        max_length=6,
    )
    minimum_source_executions: Literal[6] = Field(
        default=6,
        alias="minimumSourceExecutions",
    )
    minimum_replay_executions: Literal[6] = Field(
        default=6,
        alias="minimumReplayExecutions",
    )
    fresh_disposable_target_per_case_required: Literal[True] = Field(
        default=True,
        alias="freshDisposableTargetPerCaseRequired",
    )
    fresh_worker_execution_per_case_required: Literal[True] = Field(
        default=True,
        alias="freshWorkerExecutionPerCaseRequired",
    )
    source_and_replay_authority_disjoint_required: Literal[True] = Field(
        default=True,
        alias="sourceAndReplayAuthorityDisjointRequired",
    )
    proxy_only_worker_network_required: Literal[True] = Field(
        default=True,
        alias="proxyOnlyWorkerNetworkRequired",
    )
    no_published_target_port_required: Literal[True] = Field(
        default=True,
        alias="noPublishedTargetPortRequired",
    )
    state: Literal["registered-protocol-not-executed"] = "registered-protocol-not-executed"
    target_created: Literal[False] = Field(default=False, alias="targetCreated")
    network_created: Literal[False] = Field(default=False, alias="networkCreated")
    provider_selected: Literal[False] = Field(default=False, alias="providerSelected")
    capability_activation_authorized: Literal[False] = Field(
        default=False, alias="capabilityActivationAuthorized"
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    gateway_execution_authorized: Literal[False] = Field(
        default=False, alias="gatewayExecutionAuthorized"
    )
    worker_execution_authorized: Literal[False] = Field(
        default=False, alias="workerExecutionAuthorized"
    )
    live_measurement_authorized: Literal[False] = Field(
        default=False, alias="liveMeasurementAuthorized"
    )
    dns_authorized: Literal[False] = Field(default=False, alias="dnsAuthorized")
    udp_authorized: Literal[False] = Field(default=False, alias="udpAuthorized")
    port_range_authorized: Literal[False] = Field(default=False, alias="portRangeAuthorized")
    port_enumeration_authorized: Literal[False] = Field(
        default=False, alias="portEnumerationAuthorized"
    )
    raw_socket_authorized: Literal[False] = Field(default=False, alias="rawSocketAuthorized")
    application_protocol_write_authorized: Literal[False] = Field(
        default=False, alias="applicationProtocolWriteAuthorized"
    )
    credential_access_authorized: Literal[False] = Field(
        default=False, alias="credentialAccessAuthorized"
    )
    external_target_authorized: Literal[False] = Field(
        default=False, alias="externalTargetAuthorized"
    )
    production_target_authorized: Literal[False] = Field(
        default=False, alias="productionTargetAuthorized"
    )
    general_scanner_authorized: Literal[False] = Field(
        default=False, alias="generalScannerAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("minimum_source_executions", "minimum_replay_executions", mode="before")
    @classmethod
    def require_exact_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("NET-002A protocol counts must be exact integers")
        return value

    @field_validator(
        "fresh_disposable_target_per_case_required",
        "fresh_worker_execution_per_case_required",
        "source_and_replay_authority_disjoint_required",
        "proxy_only_worker_network_required",
        "no_published_target_port_required",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002A protocol requirements must be boolean true")
        return value

    @field_validator(*_PROTOCOL_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A protocol authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_protocol_identity(self) -> Self:
        registry = registered_network_measured_case_registry()
        private = registered_network_private_ground_truth_binding()
        emitter = registered_network_tcp_banner_emitter_profile()
        images = registered_network_image_identity_profile()
        plan = _network_domain_plan()
        case_order = tuple(case.reference() for case in registry.cases)
        if (
            self.public_registry != registry.reference()
            or self.private_ground_truth_binding_digest != private.binding_digest
            or self.emitter_profile != emitter.reference()
            or self.image_identity_profile != images.reference()
            or self.network_service_binding
            != registered_network_service_identification_binding().reference()
            or self.domain_benchmark_plan != plan.reference()
            or self.protocol_budget != NetworkServiceProtocolBudget()
            or self.source_case_order != case_order
            or self.replay_case_order != case_order
        ):
            raise ValueError("NET-002A measurement protocol differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"protocol_id", "protocol_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-measurement-protocol/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        protocol_id = f"network-measurement-protocol_{digest}"
        if self.protocol_digest and self.protocol_digest != digest:
            raise ValueError("NET-002A measurement protocol Digest differs")
        if self.protocol_id and self.protocol_id != protocol_id:
            raise ValueError("NET-002A measurement protocol ID differs")
        object.__setattr__(self, "protocol_digest", digest)
        object.__setattr__(self, "protocol_id", protocol_id)
        return self

    def reference(self) -> NetworkMeasurementProtocolRef:
        return NetworkMeasurementProtocolRef(
            protocolId=self.protocol_id,
            protocolVersion=self.protocol_version,
            protocolDigest=self.protocol_digest,
        )


class NetworkBenchmarkMetricFloorRequirement(_FrozenStrictModel):
    """One exact DOMAIN-006 Network denominator and threshold policy."""

    metric: DomainBenchmarkMetricRef
    unit: BenchmarkMetricUnit
    applicability: DomainBenchmarkMetricApplicability
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None = Field(
        default=None,
        alias="notApplicableReason",
    )
    comparison: NetworkMetricFloorComparison
    threshold_numerator: int | None = Field(
        default=None,
        alias="thresholdNumerator",
        ge=0,
        le=1_000_000_000,
    )
    threshold_denominator: int | None = Field(
        default=None,
        alias="thresholdDenominator",
        ge=1,
        le=1_000_000_000,
    )
    numerator_semantics: str | None = Field(
        default=None,
        alias="numeratorSemantics",
        max_length=240,
    )
    denominator_semantics: str | None = Field(
        default=None,
        alias="denominatorSemantics",
        max_length=240,
    )
    minimum_denominator: int | None = Field(
        default=None,
        alias="minimumDenominator",
        ge=1,
        le=1_000_000,
    )

    @field_validator(
        "threshold_numerator",
        "threshold_denominator",
        "minimum_denominator",
        mode="before",
    )
    @classmethod
    def require_strict_optional_int(cls, value: object) -> object:
        if value is not None and type(value) is not int:
            raise ValueError("NET-002A floor numbers must be exact integers")
        return value

    @model_validator(mode="after")
    def bind_requirement(self) -> Self:
        metric = resolve_registered_domain_benchmark_metric(self.metric)
        spec = _FLOOR_SPECS.get(metric.metric_id)
        if spec is None or (
            self.unit,
            self.applicability,
            self.comparison,
            self.threshold_numerator,
            self.threshold_denominator,
            self.numerator_semantics,
            self.denominator_semantics,
            self.minimum_denominator,
        ) != (
            metric.unit,
            spec.applicability,
            spec.comparison,
            spec.threshold_numerator,
            spec.threshold_denominator,
            spec.numerator_semantics,
            spec.denominator_semantics,
            spec.minimum_denominator,
        ):
            raise ValueError("NET-002A metric floor differs from code authority")
        if self.applicability is DomainBenchmarkMetricApplicability.REQUIRED:
            if self.not_applicable_reason is not None:
                raise ValueError("required NET-002A metric cannot carry an N/A reason")
        elif self.not_applicable_reason is None:
            raise ValueError("N/A NET-002A metric requires the DOMAIN-006 reason")
        return self


class NetworkValidationFloorPolicyRef(_FrozenStrictModel):
    """Exact content-addressed Network floor lookup."""

    policy_id: str = Field(
        alias="policyId",
        pattern=r"^network-validation-floor_[a-f0-9]{64}$",
    )
    policy_version: Literal["1.0.0"] = Field(alias="policyVersion")
    policy_digest: _Sha256 = Field(alias="policyDigest")


class NetworkValidationFloorPolicy(_FrozenStrictModel):
    """Registered Network metric requirements; no metric has been evaluated."""

    api_version: Literal["pajin.dev/network-validation-floor-policy/v1alpha1"] = Field(
        default=NETWORK_VALIDATION_FLOOR_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkValidationFloorPolicy"] = "NetworkValidationFloorPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=125)
    policy_version: Literal["1.0.0"] = Field(default="1.0.0", alias="policyVersion")
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    protocol: NetworkMeasurementProtocolRef
    public_registry: NetworkMeasuredCaseRegistryRef = Field(alias="publicRegistry")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    requirements: tuple[NetworkBenchmarkMetricFloorRequirement, ...] = Field(
        min_length=14,
        max_length=14,
    )
    required_policy_denial_control_count: Literal[5] = Field(
        default=5,
        alias="requiredPolicyDenialControlCount",
    )
    cleanup_is_mandatory_admission_not_numeric_action_metric: Literal[True] = Field(
        default=True,
        alias="cleanupIsMandatoryAdmissionNotNumericActionMetric",
    )
    state: Literal["registered-floor-not-evaluated"] = "registered-floor-not-evaluated"
    measurement_evaluation_authorized: Literal[False] = Field(
        default=False, alias="measurementEvaluationAuthorized"
    )
    validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="validationFloorSatisfied"
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False, alias="serviceConfirmationAuthorized"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_mutation_authorized: Literal[False] = Field(
        default=False, alias="graphMutationAuthorized"
    )
    product_projection_authorized: Literal[False] = Field(
        default=False, alias="productProjectionAuthorized"
    )
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("required_policy_denial_control_count", mode="before")
    @classmethod
    def require_exact_count(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("NET-002A denial Control count must be an exact integer")
        return value

    @field_validator("cleanup_is_mandatory_admission_not_numeric_action_metric", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002A cleanup admission requirement must be boolean true")
        return value

    @field_validator(*_FLOOR_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A floor authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        protocol = registered_network_measurement_protocol()
        registry = registered_network_measured_case_registry()
        private = registered_network_private_ground_truth_binding()
        plan = _network_domain_plan()
        if (
            self.protocol != protocol.reference()
            or self.public_registry != registry.reference()
            or self.private_ground_truth_binding_digest != private.binding_digest
            or self.domain_benchmark_plan != plan.reference()
            or self.requirements != _floor_requirements(plan)
        ):
            raise ValueError("NET-002A validation-floor policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-validation-floor-policy/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        policy_id = f"network-validation-floor_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("NET-002A validation-floor policy Digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("NET-002A validation-floor policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self

    def reference(self) -> NetworkValidationFloorPolicyRef:
        return NetworkValidationFloorPolicyRef(
            policyId=self.policy_id,
            policyVersion=self.policy_version,
            policyDigest=self.policy_digest,
        )


class NetworkMeasuredCaseAuthorityRef(_FrozenStrictModel):
    """Exact public NET-002A authority lookup."""

    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^network-measured-case-authority_[a-f0-9]{64}$",
    )
    authority_version: Literal["1.0.0"] = Field(alias="authorityVersion")
    authority_digest: _Sha256 = Field(alias="authorityDigest")


class NetworkMeasuredCaseAuthority(_FrozenStrictModel):
    """Public non-executable composition of every exact NET-002A registration."""

    api_version: Literal["pajin.dev/network-measured-case-authority/v1alpha1"] = Field(
        default=NETWORK_MEASURED_CASE_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkMeasuredCaseAuthority"] = "NetworkMeasuredCaseAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=135)
    authority_version: Literal["1.0.0"] = Field(default="1.0.0", alias="authorityVersion")
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    public_registry: NetworkMeasuredCaseRegistry = Field(alias="publicRegistry")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    emitter_profile: NetworkTCPBannerEmitterProfile = Field(alias="emitterProfile")
    image_identity_profile: NetworkImageIdentityProfile = Field(alias="imageIdentityProfile")
    measurement_protocol: NetworkMeasurementProtocol = Field(alias="measurementProtocol")
    validation_floor_policy: NetworkValidationFloorPolicy = Field(alias="validationFloorPolicy")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    state: Literal["registered-exact-network-measured-case-not-executable"] = (
        "registered-exact-network-measured-case-not-executable"
    )
    public_private_authority_separated: Literal[True] = Field(
        default=True,
        alias="publicPrivateAuthoritySeparated",
    )
    private_ground_truth_verified: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthVerified",
    )
    docker_image_build_authorized: Literal[False] = Field(
        default=False, alias="dockerImageBuildAuthorized"
    )
    target_selection_authorized: Literal[False] = Field(
        default=False, alias="targetSelectionAuthorized"
    )
    target_creation_authorized: Literal[False] = Field(
        default=False, alias="targetCreationAuthorized"
    )
    network_creation_authorized: Literal[False] = Field(
        default=False, alias="networkCreationAuthorized"
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False, alias="providerSelectionAuthorized"
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False, alias="capabilityActivationAuthorized"
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    gateway_execution_authorized: Literal[False] = Field(
        default=False, alias="gatewayExecutionAuthorized"
    )
    worker_execution_authorized: Literal[False] = Field(
        default=False, alias="workerExecutionAuthorized"
    )
    live_measurement_authorized: Literal[False] = Field(
        default=False, alias="liveMeasurementAuthorized"
    )
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="validationFloorSatisfied"
    )
    product_projection_authorized: Literal[False] = Field(
        default=False, alias="productProjectionAuthorized"
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False, alias="graphMutationAuthorized"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )
    dns_authorized: Literal[False] = Field(default=False, alias="dnsAuthorized")
    udp_authorized: Literal[False] = Field(default=False, alias="udpAuthorized")
    port_range_authorized: Literal[False] = Field(default=False, alias="portRangeAuthorized")
    port_enumeration_authorized: Literal[False] = Field(
        default=False, alias="portEnumerationAuthorized"
    )
    raw_socket_authorized: Literal[False] = Field(default=False, alias="rawSocketAuthorized")
    application_protocol_write_authorized: Literal[False] = Field(
        default=False, alias="applicationProtocolWriteAuthorized"
    )
    credential_access_authorized: Literal[False] = Field(
        default=False, alias="credentialAccessAuthorized"
    )
    external_target_authorized: Literal[False] = Field(
        default=False, alias="externalTargetAuthorized"
    )
    production_target_authorized: Literal[False] = Field(
        default=False, alias="productionTargetAuthorized"
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False, alias="serviceConfirmationAuthorized"
    )
    general_scanner_authorized: Literal[False] = Field(
        default=False, alias="generalScannerAuthorized"
    )
    caller_configuration_authorized: Literal[False] = Field(
        default=False, alias="callerConfigurationAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "public_private_authority_separated",
        "private_ground_truth_verified",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002A public/private requirements must be boolean true")
        return value

    @field_validator(*_AUTHORITY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002A authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registry = registered_network_measured_case_registry()
        private = registered_network_private_ground_truth_binding()
        emitter = registered_network_tcp_banner_emitter_profile()
        images = registered_network_image_identity_profile()
        protocol = registered_network_measurement_protocol()
        floor = registered_network_validation_floor_policy()
        plan = _network_domain_plan()
        if (
            self.public_registry != registry
            or self.private_ground_truth_binding_digest != private.binding_digest
            or self.emitter_profile != emitter
            or self.image_identity_profile != images
            or self.measurement_protocol != protocol
            or self.validation_floor_policy != floor
            or self.domain_benchmark_plan != plan.reference()
        ):
            raise ValueError("NET-002A measured-case authority differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-measured-case-authority/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        authority_id = f"network-measured-case-authority_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("NET-002A measured-case authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("NET-002A measured-case authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self

    def reference(self) -> NetworkMeasuredCaseAuthorityRef:
        return NetworkMeasuredCaseAuthorityRef(
            authorityId=self.authority_id,
            authorityVersion=self.authority_version,
            authorityDigest=self.authority_digest,
        )


@dataclass(frozen=True, slots=True)
class NetworkMeasuredCaseMapping:
    """Separated public authority and deployment-private Ground Truth binding."""

    public_authority: NetworkMeasuredCaseAuthority
    private_binding: NetworkPrivateGroundTruthBinding


@dataclass(frozen=True, slots=True)
class _FloorSpec:
    applicability: DomainBenchmarkMetricApplicability
    comparison: NetworkMetricFloorComparison
    threshold_numerator: int | None = None
    threshold_denominator: int | None = None
    numerator_semantics: str | None = None
    denominator_semantics: str | None = None
    minimum_denominator: int | None = None


_AT_LEAST = NetworkMetricFloorComparison.AT_LEAST
_FLOOR_SPECS = {
    "common.ground-truth-coverage": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "admitted-evaluable-network-ground-truth-cases",
        "registered-network-ground-truth-cases",
        6,
    ),
    "common.detection-recall": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "correct-known-positive-service-labels",
        "registered-known-positive-cases",
        5,
    ),
    "common.task-success-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        NetworkMetricFloorComparison.NOT_APPLICABLE,
    ),
    "common.false-positive-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        NetworkMetricFloorComparison.AT_MOST,
        0,
        1,
        "positive-service-labels-for-negative-controls",
        "registered-negative-control-cases",
        1,
    ),
    "common.detection-precision": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "correct-known-positive-service-labels",
        "all-positive-service-labels-produced-for-the-six-cases",
        5,
    ),
    "common.replay-or-reanalysis-success-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "successful-independent-fresh-worker-replay-cases",
        "attempted-independent-fresh-worker-replay-cases",
        6,
    ),
    "common.time-to-first-valid-result": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        NetworkMetricFloorComparison.MEASUREMENT_REQUIRED,
        numerator_semantics="elapsed-seconds-to-first-floor-eligible-network-result",
    ),
    "common.total-request-units": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        NetworkMetricFloorComparison.MEASUREMENT_REQUIRED,
        numerator_semantics="all-admitted-source-and-replay-connection-units",
    ),
    "common.total-tool-calls": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        NetworkMetricFloorComparison.MEASUREMENT_REQUIRED,
        numerator_semantics="all-admitted-source-and-replay-network-tool-calls",
    ),
    "common.total-cost-usd": _FloorSpec(
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        NetworkMetricFloorComparison.NOT_APPLICABLE,
    ),
    "common.evidence-completeness": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "verified-required-network-evidence-items",
        "registered-required-network-evidence-items",
        1,
    ),
    "common.policy-denial-correctness": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "expected-network-substitutions-denied-before-dispatch",
        "registered-code-owned-network-policy-denial-controls",
        5,
    ),
    "common.cleanup-success-rate": _FloorSpec(
        DomainBenchmarkMetricApplicability.NOT_APPLICABLE,
        NetworkMetricFloorComparison.NOT_APPLICABLE,
    ),
    "network.service-identification-accuracy": _FloorSpec(
        DomainBenchmarkMetricApplicability.REQUIRED,
        _AT_LEAST,
        1,
        1,
        "correct-known-labels-and-unresolved-negative-controls",
        "evaluated-registered-network-service-surfaces",
        6,
    ),
}


@cache
def registered_network_measured_case_registry() -> NetworkMeasuredCaseRegistry:
    """Return only the public-safe exact six-case membership."""

    return NetworkMeasuredCaseRegistry(cases=_registered_public_cases())


@cache
def registered_network_private_ground_truth_binding() -> NetworkPrivateGroundTruthBinding:
    """Return the separate deployment-private NET-001D Ground Truth binding."""

    profile = registered_network_service_benchmark_fixture_profile()
    return NetworkPrivateGroundTruthBinding(
        publicRegistry=registered_network_measured_case_registry().reference(),
        net001dProfileId=profile.profile_id,
        net001dProfileDigest=profile.profile_digest,
        cases=_registered_private_cases(),
    )


@cache
def registered_network_tcp_banner_emitter_profile() -> NetworkTCPBannerEmitterProfile:
    """Register the fixed case-ID-only emitter profile without building an image."""

    registry = registered_network_measured_case_registry()
    return NetworkTCPBannerEmitterProfile(
        publicRegistry=registry.reference(),
        cases=tuple(case.reference() for case in registry.cases),
    )


@cache
def registered_network_image_identity_profile() -> NetworkImageIdentityProfile:
    """Register immutable role contracts while leaving observed OCI IDs unbound."""

    return NetworkImageIdentityProfile(roles=_registered_image_contracts())


@cache
def registered_network_measurement_protocol() -> NetworkMeasurementProtocol:
    """Register source and independent Replay requirements without dispatching either."""

    registry = registered_network_measured_case_registry()
    private = registered_network_private_ground_truth_binding()
    case_order = tuple(case.reference() for case in registry.cases)
    return NetworkMeasurementProtocol(
        publicRegistry=registry.reference(),
        privateGroundTruthBindingDigest=private.binding_digest,
        emitterProfile=registered_network_tcp_banner_emitter_profile().reference(),
        imageIdentityProfile=registered_network_image_identity_profile().reference(),
        networkServiceBinding=registered_network_service_identification_binding().reference(),
        domainBenchmarkPlan=_network_domain_plan().reference(),
        protocolBudget=NetworkServiceProtocolBudget(),
        sourceCaseOrder=case_order,
        replayCaseOrder=case_order,
    )


@cache
def registered_network_validation_floor_policy() -> NetworkValidationFloorPolicy:
    """Register exact DOMAIN-006 Network floor semantics without evaluating a value."""

    protocol = registered_network_measurement_protocol()
    registry = registered_network_measured_case_registry()
    private = registered_network_private_ground_truth_binding()
    plan = _network_domain_plan()
    return NetworkValidationFloorPolicy(
        protocol=protocol.reference(),
        publicRegistry=registry.reference(),
        privateGroundTruthBindingDigest=private.binding_digest,
        domainBenchmarkPlan=plan.reference(),
        requirements=_floor_requirements(plan),
    )


@cache
def registered_network_measured_case_authority() -> NetworkMeasuredCaseAuthority:
    """Return the exact public NET-002A composition with every runtime authority false."""

    private = registered_network_private_ground_truth_binding()
    return NetworkMeasuredCaseAuthority(
        publicRegistry=registered_network_measured_case_registry(),
        privateGroundTruthBindingDigest=private.binding_digest,
        emitterProfile=registered_network_tcp_banner_emitter_profile(),
        imageIdentityProfile=registered_network_image_identity_profile(),
        measurementProtocol=registered_network_measurement_protocol(),
        validationFloorPolicy=registered_network_validation_floor_policy(),
        domainBenchmarkPlan=_network_domain_plan().reference(),
    )


@cache
def registered_network_measured_case_mapping() -> NetworkMeasuredCaseMapping:
    """Return public authority and private binding as separate Python objects."""

    public = registered_network_measured_case_authority()
    private = registered_network_private_ground_truth_binding()
    if public.private_ground_truth_binding_digest != private.binding_digest:
        raise NetworkMeasuredCaseAuthorityError("NET-002A public/private binding failed closed")
    return NetworkMeasuredCaseMapping(public_authority=public, private_binding=private)


def load_network_measured_case_authority(
    authority: NetworkMeasuredCaseAuthority,
    *,
    private_ground_truth_binding: NetworkPrivateGroundTruthBinding,
) -> NetworkMeasuredCaseAuthority:
    """Contextfully reload both separated artifacts from current code authority."""

    try:
        candidate = NetworkMeasuredCaseAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        private_candidate = NetworkPrivateGroundTruthBinding.model_validate(
            private_ground_truth_binding.model_dump(mode="json", by_alias=True)
        )
        expected = registered_network_measured_case_mapping()
        if (
            candidate != expected.public_authority
            or private_candidate != expected.private_binding
            or candidate.private_ground_truth_binding_digest != private_candidate.binding_digest
        ):
            raise ValueError("NET-002A public/private artifacts differ from current registration")
        return expected.public_authority.model_copy(deep=True)
    except NetworkMeasuredCaseAuthorityError:
        raise
    except (AttributeError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
        raise NetworkMeasuredCaseAuthorityError(
            "NET-002A measured-case authority reload failed closed"
        ) from exc


@cache
def _registered_private_cases() -> tuple[NetworkPrivateGroundTruthCase, ...]:
    profile = registered_network_service_benchmark_fixture_profile()
    return tuple(
        NetworkPrivateGroundTruthCase(
            caseId=fixture.fixture_id,
            fixture=fixture,
            expectedClassifierOutcome=(
                NetworkExpectedClassifierOutcome.EXACT_SERVICE_LABEL
                if fixture.expected_service_name is not None
                else NetworkExpectedClassifierOutcome.PROTOCOL_LABEL_UNRESOLVED
            ),
        )
        for fixture in profile.cases
    )


@cache
def _registered_public_cases() -> tuple[NetworkMeasuredCaseRegistration, ...]:
    return tuple(
        NetworkMeasuredCaseRegistration(
            caseId=private.case_id,
            groundTruthClass=private.fixture.ground_truth_class,
            privateGroundTruthCaseDigest=private.case_digest,
            measurementRole=(
                "classifier-positive"
                if private.fixture.ground_truth_class
                is NetworkBenchmarkGroundTruthClass.KNOWN_POSITIVE
                else "classifier-negative-control"
            ),
        )
        for private in _registered_private_cases()
    )


@cache
def _registered_image_contracts() -> tuple[NetworkImageContractIdentity, ...]:
    return tuple(
        NetworkImageContractIdentity(
            role=role,
            componentId=_image_contract(role)[0],
            contractDigest=_image_contract(role)[1],
        )
        for role in (
            NetworkMeasurementImageRole.TARGET,
            NetworkMeasurementImageRole.WORKER,
            NetworkMeasurementImageRole.PROXY,
        )
    )


@cache
def _image_contract(role: NetworkMeasurementImageRole) -> tuple[str, str]:
    if role is NetworkMeasurementImageRole.TARGET:
        return (
            "pajin.network.fixed-case-tcp-banner-emitter",
            registered_network_tcp_banner_emitter_profile().profile_digest,
        )
    if role is NetworkMeasurementImageRole.WORKER:
        return (
            "pajin.worker.network-passive-service-identification",
            registered_network_service_identification_binding().binding_digest,
        )
    proxy_material = {
        "componentId": "pajin.egress-proxy.network-fixture-connect",
        "connectionMode": "one-exact-ip-literal-tcp-connect",
        "targetNetworkAttachment": "exact-current-fixture-network-only",
        "trustedConnectReceiptRequired": True,
        "workerNetworkAttachment": "proxy-only",
    }
    return (
        "pajin.egress-proxy.network-fixture-connect",
        benchmark_digest(
            "pajin.workflow.network-proxy-image-contract/v1",
            proxy_material,
            max_bytes=_MAX_CANONICAL_BYTES,
        ),
    )


@cache
def _network_domain_plan() -> RegisteredDomainBenchmarkPlan:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.NETWORK:
            exact = resolve_registered_domain_benchmark_plan(plan.reference())
            if exact.validation_strategy is DomainValidationStrategy.FRESH_WORKER_PROTOCOL_REPLAY:
                return exact
    raise NetworkMeasuredCaseAuthorityError("DOMAIN-006 exact Network plan is missing")


def _floor_requirements(
    plan: RegisteredDomainBenchmarkPlan,
) -> tuple[NetworkBenchmarkMetricFloorRequirement, ...]:
    return tuple(
        _floor_requirement(
            requirement.metric,
            requirement.applicability,
            requirement.not_applicable_reason,
        )
        for requirement in plan.metric_requirements
    )


def _floor_requirement(
    metric_ref: DomainBenchmarkMetricRef,
    applicability: DomainBenchmarkMetricApplicability,
    not_applicable_reason: DomainBenchmarkNotApplicableReason | None,
) -> NetworkBenchmarkMetricFloorRequirement:
    metric = resolve_registered_domain_benchmark_metric(metric_ref)
    spec = _FLOOR_SPECS.get(metric.metric_id)
    if spec is None or applicability is not spec.applicability:
        raise NetworkMeasuredCaseAuthorityError("DOMAIN-006 Network metric floor is incomplete")
    return NetworkBenchmarkMetricFloorRequirement(
        metric=metric_ref,
        unit=metric.unit,
        applicability=applicability,
        notApplicableReason=not_applicable_reason,
        comparison=spec.comparison,
        thresholdNumerator=spec.threshold_numerator,
        thresholdDenominator=spec.threshold_denominator,
        numeratorSemantics=spec.numerator_semantics,
        denominatorSemantics=spec.denominator_semantics,
        minimumDenominator=spec.minimum_denominator,
    )


__all__ = [
    "NETWORK_IMAGE_IDENTITY_PROFILE_API_VERSION",
    "NETWORK_MEASURED_CASE_AUTHORITY_API_VERSION",
    "NETWORK_MEASURED_CASE_REGISTRY_API_VERSION",
    "NETWORK_MEASUREMENT_PROTOCOL_API_VERSION",
    "NETWORK_PRIVATE_GROUND_TRUTH_BINDING_API_VERSION",
    "NETWORK_TCP_BANNER_EMITTER_PORT",
    "NETWORK_TCP_BANNER_EMITTER_PROFILE_API_VERSION",
    "NETWORK_VALIDATION_FLOOR_POLICY_API_VERSION",
    "NetworkBenchmarkMetricFloorRequirement",
    "NetworkExpectedClassifierOutcome",
    "NetworkImageContractIdentity",
    "NetworkImageIdentityProfile",
    "NetworkImageIdentityProfileRef",
    "NetworkMeasuredCaseAuthority",
    "NetworkMeasuredCaseAuthorityError",
    "NetworkMeasuredCaseAuthorityRef",
    "NetworkMeasuredCaseMapping",
    "NetworkMeasuredCaseRef",
    "NetworkMeasuredCaseRegistration",
    "NetworkMeasuredCaseRegistry",
    "NetworkMeasuredCaseRegistryRef",
    "NetworkMeasurementImageRole",
    "NetworkMeasurementProtocol",
    "NetworkMeasurementProtocolRef",
    "NetworkMetricFloorComparison",
    "NetworkPrivateGroundTruthBinding",
    "NetworkPrivateGroundTruthCase",
    "NetworkTCPBannerEmitterProfile",
    "NetworkTCPBannerEmitterProfileRef",
    "NetworkValidationFloorPolicy",
    "NetworkValidationFloorPolicyRef",
    "load_network_measured_case_authority",
    "registered_network_image_identity_profile",
    "registered_network_measured_case_authority",
    "registered_network_measured_case_mapping",
    "registered_network_measured_case_registry",
    "registered_network_measurement_protocol",
    "registered_network_private_ground_truth_binding",
    "registered_network_tcp_banner_emitter_profile",
    "registered_network_validation_floor_policy",
]
