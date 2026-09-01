"""NET-002B registry-governed disposable fixture source measurement."""

from __future__ import annotations

import json
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self
from uuid import uuid4

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.network_service import (
    NetworkServiceCapabilityActivation,
    NetworkServiceIdentificationPreparation,
    prepare_network_service_identification,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.discovery import (
    NetworkAddressFamily,
    NetworkHostServiceSurface,
    NetworkTransportProtocol,
    network_host_surface_locator,
    network_port_surface_locator,
    typed_network_host_service_surface,
)
from pajin.domain.models import CampaignManifest, StrictModel, ToolResult
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalInputAuthority,
    ActionApprovalIssuerAuthorityBinding,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import ActionPermit, MissionEnvelope
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.policy.engine import PolicyEngine
from pajin.policy.scope import InvalidScopeURL, normalize_scope_pattern
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.runtime.worker import DockerWorkerBackend, WorkerResult
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway
from pajin.tools.network import (
    NetworkServiceIdentificationTool,
    network_service_scope_allow_rule,
)
from pajin.workflow.network_fixture_runtime import (
    NETWORK_WORKER_IMAGE,
    NetworkDockerBoundaryInspector,
    NetworkFixtureDockerProvider,
    NetworkFixtureLiveTarget,
    NetworkFixtureRuntimeError,
    NetworkFixtureTargetCoordinate,
    NetworkFixtureTargetLifecycleEvidence,
    NetworkFixtureTargetLifecycleRunner,
    NetworkSourceImageBinding,
    NetworkSourceImageBindingRef,
    load_network_source_image_binding,
)
from pajin.workflow.network_measured_case_authority import (
    NetworkExpectedClassifierOutcome,
    NetworkMeasuredCaseAuthority,
    NetworkMeasuredCaseAuthorityRef,
    NetworkMeasuredCaseMapping,
    NetworkMeasuredCaseRef,
    NetworkMeasurementImageRole,
    NetworkMeasurementProtocolRef,
    NetworkPrivateGroundTruthBinding,
    NetworkPrivateGroundTruthCase,
    load_network_measured_case_authority,
)
from pajin.workflow.network_service_admission import (
    NetworkServiceObservationSourceInputs,
    VerifiedNetworkServiceObservationSource,
    load_verified_network_service_observation_source,
)

NETWORK_SOURCE_CASE_LINEAGE_API_VERSION: Literal[
    "pajin.dev/network-source-case-lineage/v1alpha1"
] = "pajin.dev/network-source-case-lineage/v1alpha1"
NETWORK_SOURCE_DENIAL_RECEIPT_API_VERSION: Literal[
    "pajin.dev/network-source-denial-receipt/v1alpha1"
] = "pajin.dev/network-source-denial-receipt/v1alpha1"
NETWORK_SOURCE_MEASUREMENT_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/network-source-measurement-authority/v1alpha1"
] = "pajin.dev/network-source-measurement-authority/v1alpha1"
NETWORK_PRIVATE_SOURCE_MEASUREMENT_BINDING_API_VERSION: Literal[
    "pajin.dev/network-private-source-measurement-binding/v1alpha1"
] = "pajin.dev/network-private-source-measurement-binding/v1alpha1"

_PUBLIC_AUTHORITY_ARTIFACT = "network-source-measurement-authority.json"
_PRIVATE_AUTHORITY_ARTIFACT = "private/network-source-measurement-binding.json"
_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_ServiceName = Annotated[str, Field(pattern=r"^(ftp|imap|pop3|smtp|ssh)$")]
_AUTHORITY_TRUE_FIELDS = (
    "source_measurement_observed",
    "exact_case_membership_verified",
    "separate_approval_per_case_verified",
    "one_use_permit_per_case_verified",
    "trusted_connect_receipts_verified",
    "proxy_only_topology_verified",
    "immutable_image_identity_verified",
    "target_cleanup_verified",
    "private_output_custody_verified",
    "pre_dispatch_denial_set_verified",
)
_AUTHORITY_FALSE_FIELDS = (
    "replay_authorized",
    "measurement_floor_evaluated",
    "validation_floor_satisfied",
    "service_confirmation_authorized",
    "graph_admission_authorized",
    "graph_mutation_authorized",
    "finding_authority",
    "product_projection_authorized",
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
    "general_scanner_authorized",
    "caller_configuration_authorized",
    "additional_execution_authorized",
)


class NetworkSourceMeasurementError(RuntimeError):
    """Raised when NET-002B authority, execution, or private custody drifts."""


class NetworkSourceDenialControl(StrEnum):
    SCOPE_SUBSTITUTION = "scope-substitution"
    CASE_SUBSTITUTION = "case-substitution"
    ROUTE_SUBSTITUTION = "route-substitution"
    IMAGE_SUBSTITUTION = "image-substitution"
    AUTHORITY_SUBSTITUTION = "authority-substitution"


_DENIAL_ORDER = (
    NetworkSourceDenialControl.SCOPE_SUBSTITUTION,
    NetworkSourceDenialControl.CASE_SUBSTITUTION,
    NetworkSourceDenialControl.ROUTE_SUBSTITUTION,
    NetworkSourceDenialControl.IMAGE_SUBSTITUTION,
    NetworkSourceDenialControl.AUTHORITY_SUBSTITUTION,
)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
    )


class NetworkSourceCaseLineage(_FrozenStrictModel):
    """Public-safe case identity and sealed private Evidence commitments."""

    api_version: Literal["pajin.dev/network-source-case-lineage/v1alpha1"] = Field(
        default=NETWORK_SOURCE_CASE_LINEAGE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkSourceCaseLineage"] = "NetworkSourceCaseLineage"
    lineage_digest: str = Field(default="", alias="lineageDigest", max_length=64)
    case: NetworkMeasuredCaseRef
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    permit_digest: _Sha256 = Field(alias="permitDigest")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    target_lifecycle_evidence_digest: _Sha256 = Field(alias="targetLifecycleEvidenceDigest")
    private_case_measurement_digest: _Sha256 = Field(alias="privateCaseMeasurementDigest")
    measurement_state: Literal["approved-proxy-only-source-complete"] = Field(
        default="approved-proxy-only-source-complete",
        alias="measurementState",
    )

    @model_validator(mode="after")
    def bind_lineage(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"lineage_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-source-case-lineage/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.lineage_digest and self.lineage_digest != digest:
            raise ValueError("Network source case lineage Digest differs")
        object.__setattr__(self, "lineage_digest", digest)
        return self


class NetworkSourceDenialReceipt(_FrozenStrictModel):
    """Public-safe proof that one code-owned substitution never reached dispatch."""

    api_version: Literal["pajin.dev/network-source-denial-receipt/v1alpha1"] = Field(
        default=NETWORK_SOURCE_DENIAL_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkSourceDenialReceipt"] = "NetworkSourceDenialReceipt"
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    control: NetworkSourceDenialControl
    stage: Literal["pre-dispatch"] = "pre-dispatch"
    denied: Literal[True] = True
    dispatch_invocation_count: Literal[0] = Field(
        default=0,
        alias="dispatchInvocationCount",
    )
    denial_semantics: Literal["code-owned-substitution-rejected"] = Field(
        default="code-owned-substitution-rejected",
        alias="denialSemantics",
    )

    @field_validator("denied", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Network source denial marker must be boolean true")
        return value

    @field_validator("dispatch_invocation_count", mode="before")
    @classmethod
    def require_zero_dispatch(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("Network source denial dispatch count must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-source-denial-receipt/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Network source denial receipt Digest differs")
        object.__setattr__(self, "receipt_digest", digest)
        return self


class NetworkSourceMeasurementAuthorityRef(_FrozenStrictModel):
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^network-source-measurement_[a-f0-9]{64}$",
    )
    authority_digest: _Sha256 = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.authority_id != f"network-source-measurement_{self.authority_digest}":
            raise ValueError("Network Source Measurement Authority reference differs")
        return self


class NetworkSourceMeasurementAuthority(_FrozenStrictModel):
    """Public-safe six-case NET-002B completion authority without raw output."""

    api_version: Literal["pajin.dev/network-source-measurement-authority/v1alpha1"] = Field(
        default=NETWORK_SOURCE_MEASUREMENT_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkSourceMeasurementAuthority"] = "NetworkSourceMeasurementAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    measured_case_authority: NetworkMeasuredCaseAuthorityRef = Field(alias="measuredCaseAuthority")
    measurement_protocol: NetworkMeasurementProtocolRef = Field(alias="measurementProtocol")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    images: NetworkSourceImageBindingRef
    action_authority_context_digest: _Sha256 = Field(alias="actionAuthorityContextDigest")
    cases: tuple[NetworkSourceCaseLineage, ...] = Field(min_length=6, max_length=6)
    denials: tuple[NetworkSourceDenialReceipt, ...] = Field(min_length=5, max_length=5)
    state: Literal["registry-governed-private-source-measurement-complete"] = (
        "registry-governed-private-source-measurement-complete"
    )
    source_measurement_observed: Literal[True] = Field(
        default=True,
        alias="sourceMeasurementObserved",
    )
    exact_case_membership_verified: Literal[True] = Field(
        default=True,
        alias="exactCaseMembershipVerified",
    )
    separate_approval_per_case_verified: Literal[True] = Field(
        default=True,
        alias="separateApprovalPerCaseVerified",
    )
    one_use_permit_per_case_verified: Literal[True] = Field(
        default=True,
        alias="oneUsePermitPerCaseVerified",
    )
    trusted_connect_receipts_verified: Literal[True] = Field(
        default=True,
        alias="trustedConnectReceiptsVerified",
    )
    proxy_only_topology_verified: Literal[True] = Field(
        default=True,
        alias="proxyOnlyTopologyVerified",
    )
    immutable_image_identity_verified: Literal[True] = Field(
        default=True,
        alias="immutableImageIdentityVerified",
    )
    target_cleanup_verified: Literal[True] = Field(
        default=True,
        alias="targetCleanupVerified",
    )
    private_output_custody_verified: Literal[True] = Field(
        default=True,
        alias="privateOutputCustodyVerified",
    )
    pre_dispatch_denial_set_verified: Literal[True] = Field(
        default=True,
        alias="preDispatchDenialSetVerified",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    measurement_floor_evaluated: Literal[False] = Field(
        default=False,
        alias="measurementFloorEvaluated",
    )
    validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="validationFloorSatisfied",
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="graphMutationAuthorized",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    product_projection_authorized: Literal[False] = Field(
        default=False,
        alias="productProjectionAuthorized",
    )
    reporting_authorized: Literal[False] = Field(
        default=False,
        alias="reportingAuthorized",
    )
    external_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="externalDeliveryAuthorized",
    )
    dns_authorized: Literal[False] = Field(default=False, alias="dnsAuthorized")
    udp_authorized: Literal[False] = Field(default=False, alias="udpAuthorized")
    port_range_authorized: Literal[False] = Field(
        default=False,
        alias="portRangeAuthorized",
    )
    port_enumeration_authorized: Literal[False] = Field(
        default=False,
        alias="portEnumerationAuthorized",
    )
    raw_socket_authorized: Literal[False] = Field(
        default=False,
        alias="rawSocketAuthorized",
    )
    application_protocol_write_authorized: Literal[False] = Field(
        default=False,
        alias="applicationProtocolWriteAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    external_target_authorized: Literal[False] = Field(
        default=False,
        alias="externalTargetAuthorized",
    )
    production_target_authorized: Literal[False] = Field(
        default=False,
        alias="productionTargetAuthorized",
    )
    general_scanner_authorized: Literal[False] = Field(
        default=False,
        alias="generalScannerAuthorized",
    )
    caller_configuration_authorized: Literal[False] = Field(
        default=False,
        alias="callerConfigurationAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(*_AUTHORITY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002B verification markers must be boolean true")
        return value

    @field_validator(*_AUTHORITY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002B authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        case_ids = tuple(item.case.case_id for item in self.cases)
        if (
            len(set(case_ids)) != 6
            or len({item.source_run_id for item in self.cases}) != 6
            or len({item.permit_digest for item in self.cases}) != 6
            or len({item.approval_receipt_digest for item in self.cases}) != 6
            or tuple(item.control for item in self.denials) != _DENIAL_ORDER
            or any(item.dispatch_invocation_count != 0 for item in self.denials)
        ):
            raise ValueError("Network source membership, freshness, or denial order differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-source-measurement-authority/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        authority_id = f"network-source-measurement_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Network Source Measurement Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Network Source Measurement Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self

    def reference(self) -> NetworkSourceMeasurementAuthorityRef:
        return NetworkSourceMeasurementAuthorityRef(
            authorityId=self.authority_id,
            authorityDigest=self.authority_digest,
        )


class NetworkPrivateSourceCaseMeasurement(_FrozenStrictModel):
    """Deployment-private raw output and runtime identity for one exact source case."""

    case_measurement_digest: str = Field(
        default="",
        alias="caseMeasurementDigest",
        max_length=64,
    )
    case: NetworkPrivateGroundTruthCase
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    approval_receipt_id: _Identifier = Field(alias="approvalReceiptId")
    approval_receipt_digest: _Sha256 = Field(alias="approvalReceiptDigest")
    permit_id: _Identifier = Field(alias="permitId")
    permit_digest: _Sha256 = Field(alias="permitDigest")
    reservation_path: str = Field(alias="reservationPath", min_length=1, max_length=500)
    reservation_sha256: _Sha256 = Field(alias="reservationSha256")
    execution_evidence_path: str = Field(
        alias="executionEvidencePath",
        min_length=1,
        max_length=500,
    )
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    lifecycle: NetworkFixtureTargetLifecycleEvidence
    worker_result: WorkerResult = Field(alias="workerResult")
    tool_result: ToolResult = Field(alias="toolResult")
    raw_banner_base64: str = Field(alias="rawBannerBase64", min_length=1, max_length=1368)
    observed_service_name: _ServiceName | None = Field(
        default=None,
        alias="observedServiceName",
    )
    connect_receipt_count: Literal[1] = Field(default=1, alias="connectReceiptCount")
    application_write_bytes: Literal[0] = Field(
        default=0,
        alias="applicationWriteBytes",
    )
    synthetic_classifier_measurement_only: Literal[True] = Field(
        default=True,
        alias="syntheticClassifierMeasurementOnly",
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )

    @field_validator("synthetic_classifier_measurement_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Network source synthetic measurement marker must be true")
        return value

    @field_validator("service_confirmation_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Network source cannot grant service confirmation")
        return value

    @model_validator(mode="after")
    def bind_private_measurement(self) -> Self:
        fixture = self.case.fixture
        data = self.tool_result.data
        try:
            raw = b64decode(self.raw_banner_base64, validate=True)
        except (BinasciiError, ValueError) as exc:
            raise ValueError("Network private source banner is not canonical base64") from exc
        expected_outcome = (
            NetworkExpectedClassifierOutcome.EXACT_SERVICE_LABEL
            if fixture.expected_service_name is not None
            else NetworkExpectedClassifierOutcome.PROTOCOL_LABEL_UNRESOLVED
        )
        if (
            self.case.expected_classifier_outcome is not expected_outcome
            or fixture.fixture_id != self.lifecycle.attempt.case.case_id
            or self.source_run_id == self.lifecycle.attempt.attempt_id
            or b64encode(raw).decode("ascii") != self.raw_banner_base64
            or self.raw_banner_base64 != fixture.banner_base64
            or sha256(raw).hexdigest() != fixture.banner_sha256
            or data.get("bannerBase64") != self.raw_banner_base64
            or data.get("bannerSha256") != fixture.banner_sha256
            or data.get("bannerBytes") != len(raw)
            or data.get("connected") is not True
            or data.get("host") != self.lifecycle.coordinate.host
            or data.get("port") != self.lifecycle.coordinate.port
            or data.get("serviceName") != fixture.expected_service_name
            or self.observed_service_name != fixture.expected_service_name
            or self.worker_result.execution_id != self.lifecycle.topology.execution_id
            or self.tool_result.success is not True
            or self.tool_result.error is not None
        ):
            raise ValueError("Network private source output differs from Ground Truth")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"case_measurement_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-private-source-case-measurement/v1",
            material,
            max_bytes=8 * 1024 * 1024,
        )
        if self.case_measurement_digest and self.case_measurement_digest != digest:
            raise ValueError("Network private source case Digest differs")
        object.__setattr__(self, "case_measurement_digest", digest)
        return self


class NetworkPrivateSourceMeasurementBinding(_FrozenStrictModel):
    """Separate deployment-private NET-002B raw output and Docker evidence."""

    api_version: Literal["pajin.dev/network-private-source-measurement-binding/v1alpha1"] = Field(
        default=NETWORK_PRIVATE_SOURCE_MEASUREMENT_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkPrivateSourceMeasurementBinding"] = (
        "NetworkPrivateSourceMeasurementBinding"
    )
    binding_id: str = Field(default="", alias="bindingId", max_length=120)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    public_authority: NetworkSourceMeasurementAuthorityRef = Field(alias="publicAuthority")
    private_ground_truth_binding_id: _Identifier = Field(alias="privateGroundTruthBindingId")
    private_ground_truth_binding_digest: _Sha256 = Field(alias="privateGroundTruthBindingDigest")
    images: NetworkSourceImageBinding
    cases: tuple[NetworkPrivateSourceCaseMeasurement, ...] = Field(
        min_length=6,
        max_length=6,
    )
    visibility: Literal["deployment-private"] = "deployment-private"
    raw_banner_public_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="rawBannerPublicDisclosureAuthorized",
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="serviceConfirmationAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )

    @field_validator(
        "raw_banner_public_disclosure_authorized",
        "service_confirmation_authorized",
        "additional_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Network private source authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_private_authority(self) -> Self:
        case_digests = tuple(item.case_measurement_digest for item in self.cases)
        if (
            len(set(case_digests)) != 6
            or len({item.case.case_id for item in self.cases}) != 6
            or len({item.source_run_id for item in self.cases}) != 6
            or len({item.lifecycle.attempt.attempt_id for item in self.cases}) != 6
        ):
            raise ValueError("Network private source case membership differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-private-source-measurement-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"network-private-source-measurement_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Network private source binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Network private source binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


@dataclass(frozen=True, slots=True)
class NetworkSourceMeasurementMapping:
    public_authority: NetworkSourceMeasurementAuthority
    private_binding: NetworkPrivateSourceMeasurementBinding


@dataclass(frozen=True, slots=True)
class NetworkSourceApprovedAction:
    """Deployment-owned normal approval inputs compiled after Target inspection."""

    activation: NetworkServiceCapabilityActivation
    campaign: CampaignManifest
    preparation: NetworkServiceIdentificationPreparation
    job: CapabilityGraphCampaignJobInput
    mission_envelope: MissionEnvelope
    graph_store: SQLiteGraphStore
    approval_input_authority: ActionApprovalInputAuthority
    approval_issuer: ActionApprovalIssuerAuthorityBinding
    authority_context_digest: str


class NetworkSourceActionAuthorizer(Protocol):
    """Deployment authority that creates one fresh approval plan per inspected Target."""

    def stable_authority_context(self) -> Mapping[str, object]: ...

    def authorize(
        self,
        *,
        case: NetworkMeasuredCaseRef,
        target: NetworkFixtureTargetCoordinate,
        run_id: str,
        request_id: str,
    ) -> NetworkSourceApprovedAction: ...


@dataclass(frozen=True, slots=True)
class NetworkSourceExecutionContext:
    source_inputs: NetworkServiceObservationSourceInputs
    graph_store: SQLiteGraphStore
    lifecycle: NetworkFixtureTargetLifecycleEvidence


@dataclass(frozen=True, slots=True)
class NetworkSourceMeasurementOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    private_binding_path: str
    mapping: NetworkSourceMeasurementMapping
    executions: tuple[NetworkSourceExecutionContext, ...]


@dataclass(frozen=True, slots=True)
class _ExecutedNetworkSource:
    source: VerifiedNetworkServiceObservationSource
    source_inputs: NetworkServiceObservationSourceInputs
    graph_store: SQLiteGraphStore
    run_path: Path


def _canonical_authority_context(
    authorizer: NetworkSourceActionAuthorizer,
) -> tuple[dict[str, object], str]:
    try:
        raw = authorizer.stable_authority_context()
        encoded = json.dumps(
            raw,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        parsed = json.loads(encoded)
    except (AttributeError, OverflowError, TypeError, ValueError) as exc:
        raise NetworkSourceMeasurementError(
            "Network source action authority context is not canonical JSON"
        ) from exc
    if type(parsed) is not dict or len(encoded) > 1024 * 1024:
        raise NetworkSourceMeasurementError(
            "Network source action authority context is not a bounded object"
        )
    digest = benchmark_digest(
        "pajin.workflow.network-source-action-authority-context/v1",
        parsed,
        max_bytes=1024 * 1024,
    )
    return parsed, digest


def _expected_surface(target: NetworkFixtureTargetCoordinate) -> NetworkHostServiceSurface:
    return typed_network_host_service_surface(
        locator=network_port_surface_locator(
            host=network_host_surface_locator(
                address_family=NetworkAddressFamily.IPV4,
                host=target.host,
            ),
            transport_protocol=NetworkTransportProtocol.TCP,
            port=target.port,
        )
    )


def _canonical_backend_context(backend: DockerWorkerBackend) -> dict[str, object]:
    if type(backend) is not DockerWorkerBackend:
        raise NetworkSourceMeasurementError(
            "Network source execution requires the exact Docker Worker backend"
        )
    try:
        encoded = json.dumps(
            backend.stable_execution_context(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        parsed = json.loads(encoded)
    except (OverflowError, TypeError, ValueError) as exc:
        raise NetworkSourceMeasurementError(
            "Network source Docker backend context is invalid"
        ) from exc
    if type(parsed) is not dict or len(encoded) > 1024 * 1024:
        raise NetworkSourceMeasurementError("Network source Docker backend context is not bounded")
    return parsed


def _validate_source_pre_dispatch(
    plan: NetworkSourceApprovedAction,
    *,
    expected_case: NetworkMeasuredCaseRef,
    target: NetworkFixtureTargetCoordinate,
    images: NetworkSourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    backend_context: Mapping[str, object] | None = None,
    inspector: NetworkDockerBoundaryInspector,
) -> None:
    """Fail closed on every caller, Target, route, image, or authority substitution."""

    if type(plan) is not NetworkSourceApprovedAction:
        raise NetworkSourceMeasurementError(
            "Network source action plan requires its exact deployment type"
        )
    if (
        not isinstance(plan.activation, NetworkServiceCapabilityActivation)
        or not isinstance(plan.graph_store, SQLiteGraphStore)
        or not callable(getattr(plan.approval_input_authority, "verify_action_approval", None))
    ):
        raise NetworkSourceMeasurementError("Network source action authority inputs are invalid")
    try:
        case = NetworkMeasuredCaseRef.model_validate_json(
            expected_case.model_dump_json(by_alias=True)
        )
        coordinate = NetworkFixtureTargetCoordinate.model_validate_json(
            target.model_dump_json(by_alias=True)
        )
        image_binding = NetworkSourceImageBinding.model_validate_json(
            images.model_dump_json(by_alias=True)
        )
        campaign = CampaignManifest.model_validate_json(
            plan.campaign.model_dump_json(by_alias=True)
        )
        preparation = NetworkServiceIdentificationPreparation.model_validate_json(
            plan.preparation.model_dump_json(by_alias=True)
        )
        job = CapabilityGraphCampaignJobInput.model_validate_json(
            plan.job.model_dump_json(by_alias=True)
        )
        envelope = MissionEnvelope.model_validate_json(
            plan.mission_envelope.model_dump_json(by_alias=True)
        )
        issuer = ActionApprovalIssuerAuthorityBinding.model_validate_json(
            plan.approval_issuer.model_dump_json(by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise NetworkSourceMeasurementError("Network source action plan is not canonical") from exc
    approval = job.approval
    expected_issuer = authority_context.get("approvalIssuer")
    expected_rule = network_service_scope_allow_rule(
        address_family=coordinate.address_family,
        host=coordinate.host,
        port=coordinate.port,
    )
    try:
        normalized_allow = tuple(
            normalize_scope_pattern(item) for item in campaign.spec.scope.allow
        )
        normalized_deny = tuple(normalize_scope_pattern(item) for item in campaign.spec.scope.deny)
    except InvalidScopeURL as exc:
        raise NetworkSourceMeasurementError("Network source Campaign Scope is invalid") from exc
    rebuilt = prepare_network_service_identification(
        activation=plan.activation,
        release=preparation.release,
        campaign=campaign,
        surface=_expected_surface(coordinate),
        request_id=preparation.prepared_action.request.request_id,
        agent_id=preparation.prepared_action.request.agent_id,
    )
    actual_backend_context = (
        dict(backend_context)
        if backend_context is not None
        else _canonical_backend_context(backend)
    )
    worker_image = image_binding.role(NetworkMeasurementImageRole.WORKER)
    proxy_image = image_binding.role(NetworkMeasurementImageRole.PROXY)
    target_image = image_binding.role(NetworkMeasurementImageRole.TARGET)
    expected_observer_context = dict(inspector.stable_observer_context())
    expected_backend_keys = {
        "implementationVersion",
        "allowedImages",
        "dockerExecutable",
        "egressProxyImage",
        "externalNetwork",
        "runtimeImageBindings",
        "externalNetworkRoutes",
        "egressLifecycleObserver",
    }
    if (
        case != coordinate.case
        or target_image.observed_image_id != coordinate.target_image_id
        or plan.authority_context_digest != authority_context_digest
        or not isinstance(expected_issuer, dict)
        or expected_issuer != issuer.model_dump(mode="json", by_alias=True)
        or approval is None
        or approval.issuer != issuer
        or campaign != plan.campaign
        or preparation != plan.preparation
        or job != plan.job
        or envelope != plan.mission_envelope
        or rebuilt != preparation
        or preparation.surface != _expected_surface(coordinate)
        or normalized_allow != (expected_rule,)
        or normalized_deny
        or set(campaign.spec.rules_of_engagement.allowed_methods) != {"CONNECT"}
        or campaign.spec.rules_of_engagement.allow_private_networks is not True
        or plan.graph_store.campaign_id != campaign.metadata.name
        or job.profile != "capability-graph-v1"
        or job.request != preparation.prepared_action.request
        or job.release != preparation.release
        or job.proposal.run_id != envelope.run_id
        or job.proposal.envelope_id != envelope.envelope_id
        or job.proposal.envelope_digest != envelope.envelope_digest
        or approval.mission_envelope != envelope
        or approval.proposal != job.proposal
        or approval.graph_decision != job.decision
        or set(actual_backend_context) != expected_backend_keys
        or actual_backend_context.get("implementationVersion") != "pajin.docker-worker/v4"
        or actual_backend_context.get("allowedImages") != [NETWORK_WORKER_IMAGE]
        or actual_backend_context.get("runtimeImageBindings")
        != {NETWORK_WORKER_IMAGE: worker_image.observed_image_id}
        or actual_backend_context.get("egressProxyImage") != proxy_image.observed_image_id
        or actual_backend_context.get("externalNetwork") != "bridge"
        or actual_backend_context.get("externalNetworkRoutes")
        != {"network-service-identify": coordinate.target_network_name}
        or actual_backend_context.get("egressLifecycleObserver") != expected_observer_context
        or not backend.binds_egress_lifecycle_observer(inspector)
    ):
        raise NetworkSourceMeasurementError("Network source pre-dispatch authority differs")
    if any(
        permit.run_id == envelope.run_id
        or permit.request_id == preparation.prepared_action.request.request_id
        for permit in plan.graph_store.permit_store.permits()
    ):
        raise NetworkSourceMeasurementError(
            "Network source Run, request, approval, or Permit authority was reused"
        )
    if (
        approval is not None
        and plan.graph_store.permit_store.approved_authorization(
            approval.approval_id,
            approval.expected_action_permit_id,
        )
        is not None
    ):
        raise NetworkSourceMeasurementError(
            "Network source approval authority was already consumed"
        )


def _scope_substitution(plan: NetworkSourceApprovedAction) -> NetworkSourceApprovedAction:
    payload = plan.campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"] = {
        "allow": ["https://192.0.2.1:18080/**"],
        "deny": [],
    }
    return replace(
        plan,
        campaign=CampaignManifest.model_validate_json(json.dumps(payload, separators=(",", ":"))),
    )


def _foreign_image_binding(images: NetworkSourceImageBinding) -> NetworkSourceImageBinding:
    payload = images.model_dump(mode="json", by_alias=True)
    payload["bindingId"] = ""
    payload["bindingDigest"] = ""
    roles = payload["roles"]
    if not isinstance(roles, list):
        raise NetworkSourceMeasurementError("Network source image roles are not canonical")
    for role in roles:
        if isinstance(role, dict) and role.get("role") == "worker":
            current = role.get("observedImageId")
            foreign = "sha256:" + ("0" * 64)
            if current == foreign:
                foreign = "sha256:" + ("f" * 64)
            role["observedImageId"] = foreign
            role["bindingDigest"] = ""
    return NetworkSourceImageBinding.model_validate_json(json.dumps(payload, separators=(",", ":")))


def _denial_receipt(
    control: NetworkSourceDenialControl,
) -> NetworkSourceDenialReceipt:
    return NetworkSourceDenialReceipt(control=control)


def _evaluate_code_owned_denials(
    plan: NetworkSourceApprovedAction,
    *,
    cases: tuple[NetworkMeasuredCaseRef, ...],
    target: NetworkFixtureTargetCoordinate,
    images: NetworkSourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: NetworkDockerBoundaryInspector,
) -> tuple[NetworkSourceDenialReceipt, ...]:
    valid_context = _canonical_backend_context(backend)
    foreign_route = dict(valid_context)
    foreign_route["externalNetworkRoutes"] = {
        "network-service-identify": f"{target.target_network_name}-foreign"
    }
    probes = (
        (
            NetworkSourceDenialControl.SCOPE_SUBSTITUTION,
            _scope_substitution(plan),
            cases[0],
            images,
            authority_context_digest,
            valid_context,
        ),
        (
            NetworkSourceDenialControl.CASE_SUBSTITUTION,
            plan,
            cases[1],
            images,
            authority_context_digest,
            valid_context,
        ),
        (
            NetworkSourceDenialControl.ROUTE_SUBSTITUTION,
            plan,
            cases[0],
            images,
            authority_context_digest,
            foreign_route,
        ),
        (
            NetworkSourceDenialControl.IMAGE_SUBSTITUTION,
            plan,
            cases[0],
            _foreign_image_binding(images),
            authority_context_digest,
            valid_context,
        ),
        (
            NetworkSourceDenialControl.AUTHORITY_SUBSTITUTION,
            plan,
            cases[0],
            images,
            ("0" * 64 if authority_context_digest != "0" * 64 else "f" * 64),
            valid_context,
        ),
    )
    receipts: list[NetworkSourceDenialReceipt] = []
    for control, candidate, case, candidate_images, context_digest, backend_context in probes:
        try:
            _validate_source_pre_dispatch(
                candidate,
                expected_case=case,
                target=target,
                images=candidate_images,
                authority_context=authority_context,
                authority_context_digest=context_digest,
                backend=backend,
                backend_context=backend_context,
                inspector=inspector,
            )
        except (NetworkFixtureRuntimeError, NetworkSourceMeasurementError, ValueError):
            receipts.append(_denial_receipt(control))
            continue
        raise NetworkSourceMeasurementError(
            f"Network source {control} denial reached dispatch eligibility"
        )
    return tuple(receipts)


async def _execute_approved_source(
    plan: NetworkSourceApprovedAction,
    *,
    expected_case: NetworkMeasuredCaseRef,
    target: NetworkFixtureTargetCoordinate,
    images: NetworkSourceImageBinding,
    authority_context: Mapping[str, object],
    authority_context_digest: str,
    backend: DockerWorkerBackend,
    inspector: NetworkDockerBoundaryInspector,
    source_runs_root: Path,
) -> _ExecutedNetworkSource:
    _validate_source_pre_dispatch(
        plan,
        expected_case=expected_case,
        target=target,
        images=images,
        authority_context=authority_context,
        authority_context_digest=authority_context_digest,
        backend=backend,
        inspector=inspector,
    )
    job = plan.job
    approval = job.approval
    if approval is None:
        raise NetworkSourceMeasurementError(
            "Network source execution requires one explicit approval"
        )
    run_store = RunStore.create(
        source_runs_root,
        plan.campaign.metadata.name,
        run_id=plan.mission_envelope.run_id,
    )
    tools = ToolRegistry()
    tools.register(NetworkServiceIdentificationTool())
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=tools,
        worker=backend,
        store=run_store,
    )
    permit_authority = GraphApprovedActionPermitAuthority(
        campaign_id=plan.campaign.metadata.name,
        compiler_id=plan.mission_envelope.compiler_id,
        compiler_version=plan.mission_envelope.compiler_version,
        compiler_digest=plan.mission_envelope.compiler_digest,
        capabilities=plan.activation.action_registry(),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=plan.preparation.prepared_action.capability,
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=plan.graph_store.permit_store,
        input_authority=plan.approval_input_authority,
    )
    dispatcher = GraphApprovedActionPermitDispatcher(permit_authority)

    async def dispatch(
        permit: ActionPermit,
        _receipt: ActionApprovalConsumptionReceipt,
    ) -> GatewayOutcome:
        claimed_at = datetime.now(UTC)
        claimed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.CLAIMED,
            occurredAt=claimed_at,
            activationSetDigest=plan.preparation.prepared_action.activation_set_digest,
            release=plan.preparation.release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(job.grant),
        )
        run_store.append_event(
            "capability.dispatch.claimed",
            claimed.model_dump(mode="json", by_alias=True),
            occurred_at=claimed.occurred_at,
        )
        outcome = await gateway.execute(
            plan.campaign,
            job.grant,
            plan.preparation.prepared_action.request,
            used_calls=0,
        )
        completed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.COMPLETED,
            occurredAt=datetime.now(UTC),
            activationSetDigest=plan.preparation.prepared_action.activation_set_digest,
            release=plan.preparation.release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(job.grant),
            gatewayOutcomeDigest=capability_gateway_outcome_digest(outcome),
            gatewayExecutionId=(
                outcome.worker_result.execution_id if outcome.worker_result is not None else None
            ),
            executed=outcome.executed,
            policyAllowed=outcome.decision.allowed,
            toolSuccess=outcome.result.success,
            evidence=tuple(sorted(set(outcome.result.evidence))),
        )
        run_store.append_event(
            "capability.dispatch.completed",
            completed.model_dump(mode="json", by_alias=True),
            occurred_at=completed.occurred_at,
        )
        return outcome

    dispatched = await dispatcher.dispatch_once(
        plan.mission_envelope,
        job.proposal,
        job.decision,
        approval,
        dispatch,
    )
    if dispatched.dispatched is not True or dispatched.result is None:
        raise NetworkSourceMeasurementError(
            "Network source approval or Permit was reused before dispatch"
        )
    run_store.seal()
    source_inputs = NetworkServiceObservationSourceInputs(
        run_path=run_store.path,
        expected_run_id=run_store.run_id,
        activation=plan.activation,
        campaign=plan.campaign,
        preparation=plan.preparation,
        job=job,
    )
    source = load_verified_network_service_observation_source(
        source_inputs,
        graph_store=plan.graph_store,
    )
    return _ExecutedNetworkSource(
        source=source,
        source_inputs=source_inputs,
        graph_store=plan.graph_store,
        run_path=run_store.path,
    )


def _build_private_case_measurement(
    *,
    ground_truth: NetworkPrivateGroundTruthCase,
    executed: _ExecutedNetworkSource,
    lifecycle: NetworkFixtureTargetLifecycleEvidence,
) -> NetworkPrivateSourceCaseMeasurement:
    source = executed.source
    data = source.evidence.result.data
    raw_banner = data.get("bannerBase64")
    observed_service = data.get("serviceName")
    if not isinstance(raw_banner, str) or (
        observed_service is not None and not isinstance(observed_service, str)
    ):
        raise NetworkSourceMeasurementError(
            "Network source Tool output lacks its private banner or label shape"
        )
    return NetworkPrivateSourceCaseMeasurement(
        case=ground_truth,
        sourceRunId=source.snapshot.verification.run_id,
        sourceRootDigest=source.snapshot.verification.root_digest,
        approvalReceiptId=source.approval_receipt.receipt_id,
        approvalReceiptDigest=source.approval_receipt.receipt_digest,
        permitId=source.permit.permit_id,
        permitDigest=source.permit.permit_digest,
        reservationPath=source.reservation_path,
        reservationSha256=source.reservation_sha256,
        executionEvidencePath=source.evidence_path,
        executionEvidenceSha256=source.evidence_sha256,
        lifecycle=lifecycle,
        workerResult=source.evidence.worker_result,
        toolResult=source.evidence.result,
        rawBannerBase64=raw_banner,
        observedServiceName=observed_service,
        connectReceiptCount=1,
        applicationWriteBytes=0,
    )


def _build_public_lineage(
    private: NetworkPrivateSourceCaseMeasurement,
) -> NetworkSourceCaseLineage:
    return NetworkSourceCaseLineage(
        case=private.lifecycle.attempt.case,
        sourceRunId=private.source_run_id,
        sourceRootDigest=private.source_root_digest,
        approvalReceiptDigest=private.approval_receipt_digest,
        permitDigest=private.permit_digest,
        executionEvidenceSha256=private.execution_evidence_sha256,
        targetLifecycleEvidenceDigest=private.lifecycle.evidence_digest,
        privateCaseMeasurementDigest=private.case_measurement_digest,
    )


class NetworkSourceMeasurementRunner:
    """Execute the exact six NET-002B cases with fresh Target and approval identity."""

    def __init__(
        self,
        *,
        measured_cases: NetworkMeasuredCaseMapping,
        images: NetworkSourceImageBinding,
        lifecycle: NetworkFixtureTargetLifecycleRunner,
        authorizer: NetworkSourceActionAuthorizer,
        source_runs_root: Path,
        authority_runs_root: Path,
    ) -> None:
        if type(measured_cases) is not NetworkMeasuredCaseMapping:
            raise TypeError("Network source runner requires exact measured-case mapping")
        if not isinstance(lifecycle, NetworkFixtureTargetLifecycleRunner):
            raise TypeError("Network source runner requires exact Target lifecycle")
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("Network source runner requires an action authorizer")
        try:
            authority = load_network_measured_case_authority(
                measured_cases.public_authority,
                private_ground_truth_binding=measured_cases.private_binding,
            )
            image_binding = load_network_source_image_binding(
                images,
                inspector=lifecycle.provider,
            )
        except (NetworkFixtureRuntimeError, ValueError) as exc:
            raise NetworkSourceMeasurementError(
                "Network source runner authority could not be reopened"
            ) from exc
        context, context_digest = _canonical_authority_context(authorizer)
        self._measured_authority = authority
        self._private_ground_truth = measured_cases.private_binding.model_copy(deep=True)
        self._images = image_binding
        self._lifecycle = lifecycle
        self._authorizer = authorizer
        self._authority_context = context
        self._authority_context_digest = context_digest
        self._source_runs_root = Path(source_runs_root)
        self._authority_runs_root = Path(authority_runs_root)

    async def run(self) -> NetworkSourceMeasurementOutcome:
        if self._lifecycle.reconcile_abandoned():
            raise NetworkSourceMeasurementError(
                "Network source run reconciled abandoned state; start a fresh invocation"
            )
        current_context, current_digest = _canonical_authority_context(self._authorizer)
        if (
            current_context != self._authority_context
            or current_digest != self._authority_context_digest
        ):
            raise NetworkSourceMeasurementError(
                "Network source action authority context changed before execution"
            )
        public_cases = tuple(
            item.reference() for item in self._measured_authority.public_registry.cases
        )
        private_cases = self._private_ground_truth.cases
        if tuple(item.case_id for item in public_cases) != tuple(
            item.case_id for item in private_cases
        ):
            raise NetworkSourceMeasurementError(
                "Network source public and private case order differs"
            )

        private_measurements: list[NetworkPrivateSourceCaseMeasurement] = []
        public_lineages: list[NetworkSourceCaseLineage] = []
        executions: list[NetworkSourceExecutionContext] = []
        denial_receipts: tuple[NetworkSourceDenialReceipt, ...] | None = None
        for ordinal, (case, ground_truth) in enumerate(
            zip(public_cases, private_cases, strict=True),
            start=1,
        ):
            live: NetworkFixtureLiveTarget | None = None
            lifecycle_complete = False
            try:
                live = self._lifecycle.start(case=case, images=self._images)
                inspector = self._lifecycle.provider.boundary_inspector(
                    coordinate=live.coordinate,
                    images=self._images,
                )
                worker_image = self._images.role(NetworkMeasurementImageRole.WORKER)
                proxy_image = self._images.role(NetworkMeasurementImageRole.PROXY)
                backend = DockerWorkerBackend(
                    allowed_images={NETWORK_WORKER_IMAGE},
                    egress_proxy_image=proxy_image.observed_image_id,
                    external_network_routes={
                        "network-service-identify": live.coordinate.target_network_name
                    },
                    runtime_image_bindings={NETWORK_WORKER_IMAGE: worker_image.observed_image_id},
                    egress_lifecycle_observer=inspector,
                )
                run_id = RunStore.new_run_id()
                request_id = f"tool_net002b_source_{ordinal}_{uuid4().hex}"
                plan = self._authorizer.authorize(
                    case=case.model_copy(deep=True),
                    target=live.coordinate.model_copy(deep=True),
                    run_id=run_id,
                    request_id=request_id,
                )
                if denial_receipts is None:
                    denial_receipts = _evaluate_code_owned_denials(
                        plan,
                        cases=public_cases,
                        target=live.coordinate,
                        images=self._images,
                        authority_context=self._authority_context,
                        authority_context_digest=self._authority_context_digest,
                        backend=backend,
                        inspector=inspector,
                    )
                executed = await _execute_approved_source(
                    plan,
                    expected_case=case,
                    target=live.coordinate,
                    images=self._images,
                    authority_context=self._authority_context,
                    authority_context_digest=self._authority_context_digest,
                    backend=backend,
                    inspector=inspector,
                    source_runs_root=self._source_runs_root,
                )
                topology = inspector.topology_observation(
                    executed.source.evidence.worker_result.execution_id
                )
                lifecycle_evidence = self._lifecycle.finish(
                    live,
                    topology=topology,
                )
                lifecycle_complete = True
                private = _build_private_case_measurement(
                    ground_truth=ground_truth,
                    executed=executed,
                    lifecycle=lifecycle_evidence,
                )
                private_measurements.append(private)
                public_lineages.append(_build_public_lineage(private))
                executions.append(
                    NetworkSourceExecutionContext(
                        source_inputs=executed.source_inputs,
                        graph_store=executed.graph_store,
                        lifecycle=lifecycle_evidence,
                    )
                )
                stable_context, stable_digest = _canonical_authority_context(self._authorizer)
                if (
                    stable_context != self._authority_context
                    or stable_digest != self._authority_context_digest
                ):
                    raise NetworkSourceMeasurementError(
                        "Network source action authority context changed during execution"
                    )
                if not self._lifecycle.provider.managed_resources_absent():
                    raise NetworkSourceMeasurementError(
                        "Network source Target residue remains after cleanup"
                    )
            except BaseException:
                if live is not None and not lifecycle_complete:
                    try:
                        self._lifecycle.reconcile_abandoned()
                    except Exception as cleanup_error:
                        raise NetworkSourceMeasurementError(
                            "Network source failure cleanup could not be reconciled"
                        ) from cleanup_error
                raise

        if denial_receipts is None:
            raise NetworkSourceMeasurementError("Network source denial set was not evaluated")
        public_authority = NetworkSourceMeasurementAuthority(
            measuredCaseAuthority=self._measured_authority.reference(),
            measurementProtocol=self._measured_authority.measurement_protocol.reference(),
            privateGroundTruthBindingDigest=self._private_ground_truth.binding_digest,
            images=self._images.reference(),
            actionAuthorityContextDigest=self._authority_context_digest,
            cases=tuple(public_lineages),
            denials=denial_receipts,
        )
        private_binding = NetworkPrivateSourceMeasurementBinding(
            publicAuthority=public_authority.reference(),
            privateGroundTruthBindingId=self._private_ground_truth.binding_id,
            privateGroundTruthBindingDigest=self._private_ground_truth.binding_digest,
            images=self._images,
            cases=tuple(private_measurements),
        )
        mapping = NetworkSourceMeasurementMapping(
            public_authority=public_authority,
            private_binding=private_binding,
        )
        _validate_mapping(
            mapping,
            measured_authority=self._measured_authority,
            private_ground_truth=self._private_ground_truth,
        )
        store = RunStore.create(
            self._authority_runs_root,
            "network-source-measurement",
        )
        store.write_json_create_only(
            _PUBLIC_AUTHORITY_ARTIFACT,
            public_authority.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _PRIVATE_AUTHORITY_ARTIFACT,
            private_binding.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "network.source-measurement.sealed",
            {
                "authorityDigest": public_authority.authority_digest,
                "privateBindingDigest": private_binding.binding_digest,
                "caseCount": 6,
                "denialCount": 5,
            },
        )
        store.seal()
        return NetworkSourceMeasurementOutcome(
            run_id=store.run_id,
            run_path=store.path,
            authority_path=_PUBLIC_AUTHORITY_ARTIFACT,
            private_binding_path=_PRIVATE_AUTHORITY_ARTIFACT,
            mapping=mapping,
            executions=tuple(executions),
        )


def _validate_mapping(
    mapping: NetworkSourceMeasurementMapping,
    *,
    measured_authority: NetworkMeasuredCaseAuthority,
    private_ground_truth: NetworkPrivateGroundTruthBinding,
) -> None:
    if type(mapping) is not NetworkSourceMeasurementMapping:
        raise NetworkSourceMeasurementError(
            "Network source mapping requires its exact separated type"
        )
    try:
        public = NetworkSourceMeasurementAuthority.model_validate_json(
            mapping.public_authority.model_dump_json(by_alias=True)
        )
        private = NetworkPrivateSourceMeasurementBinding.model_validate_json(
            mapping.private_binding.model_dump_json(by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise NetworkSourceMeasurementError("Network source mapping is not canonical") from exc
    expected_case_refs = tuple(
        item.reference() for item in measured_authority.public_registry.cases
    )
    private_case_ids = tuple(item.case.case_id for item in private.cases)
    public_case_refs = tuple(item.case for item in public.cases)
    target_images = {item.lifecycle.coordinate.target_image_id for item in private.cases}
    worker_images = {item.lifecycle.topology.worker_image_id for item in private.cases}
    proxy_images = {item.lifecycle.topology.proxy_image_id for item in private.cases}
    target_image_id = private.images.role(NetworkMeasurementImageRole.TARGET).observed_image_id
    worker_image_id = private.images.role(NetworkMeasurementImageRole.WORKER).observed_image_id
    proxy_image_id = private.images.role(NetworkMeasurementImageRole.PROXY).observed_image_id
    if (
        public != mapping.public_authority
        or private != mapping.private_binding
        or public.measured_case_authority != measured_authority.reference()
        or public.measurement_protocol != measured_authority.measurement_protocol.reference()
        or public.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or public.images != private.images.reference()
        or private.public_authority != public.reference()
        or private.private_ground_truth_binding_id != private_ground_truth.binding_id
        or private.private_ground_truth_binding_digest != private_ground_truth.binding_digest
        or public_case_refs != expected_case_refs
        or private_case_ids != tuple(item.case_id for item in expected_case_refs)
        or tuple(item.case for item in private.cases) != private_ground_truth.cases
        or tuple(item.private_case_measurement_digest for item in public.cases)
        != tuple(item.case_measurement_digest for item in private.cases)
        or tuple(item.target_lifecycle_evidence_digest for item in public.cases)
        != tuple(item.lifecycle.evidence_digest for item in private.cases)
        or tuple(item.source_run_id for item in public.cases)
        != tuple(item.source_run_id for item in private.cases)
        or target_images != {target_image_id}
        or worker_images != {worker_image_id}
        or proxy_images != {proxy_image_id}
        or len({item.lifecycle.coordinate.target_container_id for item in private.cases}) != 6
        or len({item.lifecycle.coordinate.target_network_id for item in private.cases}) != 6
        or len({item.lifecycle.topology.worker_container_id for item in private.cases}) != 6
        or len({item.lifecycle.topology.proxy_container_id for item in private.cases}) != 6
    ):
        raise NetworkSourceMeasurementError(
            "Network source public/private authority binding differs"
        )


def load_network_source_measurement_authority(
    outcome: NetworkSourceMeasurementOutcome,
    *,
    measured_cases: NetworkMeasuredCaseMapping,
    provider: NetworkFixtureDockerProvider,
) -> NetworkSourceMeasurementAuthority:
    """Reopen sealed public/private NET-002B artifacts and all six NET-001B Runs."""

    if type(outcome) is not NetworkSourceMeasurementOutcome:
        raise TypeError("Network source reload requires its exact outcome")
    if type(measured_cases) is not NetworkMeasuredCaseMapping:
        raise TypeError("Network source reload requires exact measured-case mapping")
    if not isinstance(provider, NetworkFixtureDockerProvider):
        raise TypeError("Network source reload requires exact Docker provider")
    try:
        measured_authority = load_network_measured_case_authority(
            measured_cases.public_authority,
            private_ground_truth_binding=measured_cases.private_binding,
        )
        public = NetworkSourceMeasurementAuthority.model_validate_json(
            outcome.mapping.public_authority.model_dump_json(by_alias=True)
        )
        private = NetworkPrivateSourceMeasurementBinding.model_validate_json(
            outcome.mapping.private_binding.model_dump_json(by_alias=True)
        )
        load_network_source_image_binding(private.images, inspector=provider)
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                outcome.authority_path: _MAX_CANONICAL_BYTES,
                outcome.private_binding_path: _MAX_CANONICAL_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_public = NetworkSourceMeasurementAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        sealed_private = NetworkPrivateSourceMeasurementBinding.model_validate_json(
            snapshot.artifact_bytes(outcome.private_binding_path)
        )
    except (
        AttributeError,
        NetworkFixtureRuntimeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise NetworkSourceMeasurementError(
            "Network source sealed authority could not be reopened"
        ) from exc
    if (
        sealed_public != public
        or sealed_private != private
        or public != outcome.mapping.public_authority
        or private != outcome.mapping.private_binding
        or len(outcome.executions) != 6
        or len({item.source_inputs.expected_run_id for item in outcome.executions}) != 6
        or any(item.source_inputs.run_path == outcome.run_path for item in outcome.executions)
    ):
        raise NetworkSourceMeasurementError(
            "Network source sealed artifacts or Run identities differ"
        )
    rebuilt_private: list[NetworkPrivateSourceCaseMeasurement] = []
    rebuilt_public: list[NetworkSourceCaseLineage] = []
    for ground_truth, execution in zip(
        measured_cases.private_binding.cases,
        outcome.executions,
        strict=True,
    ):
        try:
            source = load_verified_network_service_observation_source(
                execution.source_inputs,
                graph_store=execution.graph_store,
            )
        except Exception as exc:
            raise NetworkSourceMeasurementError(
                "Network source execution could not be contextfully reopened"
            ) from exc
        rebuilt = _build_private_case_measurement(
            ground_truth=ground_truth,
            executed=_ExecutedNetworkSource(
                source=source,
                source_inputs=execution.source_inputs,
                graph_store=execution.graph_store,
                run_path=execution.source_inputs.run_path,
            ),
            lifecycle=execution.lifecycle,
        )
        rebuilt_private.append(rebuilt)
        rebuilt_public.append(_build_public_lineage(rebuilt))
    if (
        tuple(rebuilt_private) != private.cases
        or tuple(rebuilt_public) != public.cases
        or not provider.managed_resources_absent()
    ):
        raise NetworkSourceMeasurementError(
            "Network source private output, topology, or cleanup Evidence differs"
        )
    mapping = NetworkSourceMeasurementMapping(
        public_authority=public,
        private_binding=private,
    )
    _validate_mapping(
        mapping,
        measured_authority=measured_authority,
        private_ground_truth=measured_cases.private_binding,
    )
    return public.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class NetworkSourceMeasurementReopenContext:
    """Host-owned context required to trust one sealed NET-002B result."""

    outcome: NetworkSourceMeasurementOutcome
    measured_cases: NetworkMeasuredCaseMapping
    provider: NetworkFixtureDockerProvider

    def reopen(self) -> NetworkSourceMeasurementAuthority:
        if type(self) is not NetworkSourceMeasurementReopenContext:
            raise NetworkSourceMeasurementError(
                "Network source reopen context requires its exact type"
            )
        return load_network_source_measurement_authority(
            self.outcome,
            measured_cases=self.measured_cases,
            provider=self.provider,
        )


__all__ = [
    "NETWORK_PRIVATE_SOURCE_MEASUREMENT_BINDING_API_VERSION",
    "NETWORK_SOURCE_CASE_LINEAGE_API_VERSION",
    "NETWORK_SOURCE_DENIAL_RECEIPT_API_VERSION",
    "NETWORK_SOURCE_MEASUREMENT_AUTHORITY_API_VERSION",
    "NetworkPrivateSourceCaseMeasurement",
    "NetworkPrivateSourceMeasurementBinding",
    "NetworkSourceActionAuthorizer",
    "NetworkSourceApprovedAction",
    "NetworkSourceCaseLineage",
    "NetworkSourceDenialControl",
    "NetworkSourceDenialReceipt",
    "NetworkSourceExecutionContext",
    "NetworkSourceMeasurementAuthority",
    "NetworkSourceMeasurementAuthorityRef",
    "NetworkSourceMeasurementError",
    "NetworkSourceMeasurementMapping",
    "NetworkSourceMeasurementOutcome",
    "NetworkSourceMeasurementReopenContext",
    "NetworkSourceMeasurementRunner",
    "load_network_source_measurement_authority",
]
