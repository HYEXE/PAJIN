"""NET-001D fresh Worker execution Replay and isolated-service fixture contract."""

from __future__ import annotations

from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
)
from pajin.capabilities.network_service import (
    NetworkServiceIdentificationPreparation,
    NetworkServiceProtocolBudget,
)
from pajin.capabilities.reconciliation import (
    CapabilityDispatchReconciliation,
    CapabilityDispatchReconciliationStatus,
)
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.tools.network import MAX_NETWORK_SERVICE_BANNER_BYTES
from pajin.workflow.network_service_admission import (
    NetworkProtocolKnowledgeAdmission,
    NetworkServiceObservationSourceInputs,
    VerifiedNetworkServiceObservationSource,
    load_verified_network_service_observation_source,
)

NETWORK_SERVICE_REPLAY_VALIDATION_API_VERSION: Literal[
    "pajin.dev/network-service-replay-validation/v1alpha1"
] = "pajin.dev/network-service-replay-validation/v1alpha1"
NETWORK_SERVICE_BENCHMARK_FIXTURE_PROFILE_API_VERSION: Literal[
    "pajin.dev/network-service-benchmark-fixture-profile/v1alpha1"
] = "pajin.dev/network-service-benchmark-fixture-profile/v1alpha1"

_MAX_CANONICAL_BYTES = 32 * 1024 * 1024
_MAX_BANNER_BASE64_CHARS = ((MAX_NETWORK_SERVICE_BANNER_BYTES + 2) // 3) * 4
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_ArtifactPath = Annotated[
    str,
    Field(pattern=r"^(?:evidence|requests)/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$"),
]
_ServiceName = Literal["ftp", "imap", "pop3", "smtp", "ssh"]
_ReplayState = Literal[
    "fresh-worker-replay-protocol-label-match",
    "fresh-worker-replay-protocol-label-changed",
    "fresh-worker-replay-protocol-label-unresolved",
]

_REPLAY_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_replay_reverified",
    "separate_authorization_verified",
    "distinct_worker_execution_verified",
    "fresh_connection_session_verified",
)
_REPLAY_FALSE_FIELDS = (
    "service_observation_confirmed",
    "ground_truth_case_bound",
    "negative_control_observed",
    "benchmark_measurement_observed",
    "profile_validation_floor_satisfied",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "tool_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "replay_authorized",
    "execution_authorized",
)
_FIXTURE_TRUE_FIELDS = (
    "private_ground_truth_verified",
    "isolated_fixture_required",
    "negative_control_registered",
    "fresh_worker_replay_required",
)
_FIXTURE_FALSE_FIELDS = (
    "target_profile_selected",
    "target_factory_authority",
    "provider_execution_authorized",
    "fixture_execution_authorized",
    "replay_evidence_bound",
    "benchmark_measurement_observed",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "service_observation_confirmed",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "tool_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "replay_authorized",
    "execution_authorized",
)


class NetworkServiceReplayBenchmarkError(RuntimeError):
    """Raised when a NET-001D predecessor or benchmark coordinate differs."""


class NetworkProtocolLabelComparison(StrEnum):
    """Neutral comparison states; none of them confirms a service."""

    MATCHED = "protocol-label-match"
    CHANGED = "protocol-label-changed"
    UNRESOLVED = "protocol-label-unresolved"


class NetworkBenchmarkGroundTruthClass(StrEnum):
    """Closed isolated fixture vocabulary for future measurements."""

    KNOWN_POSITIVE = "known-positive"
    NEGATIVE_CONTROL = "negative-control"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class NetworkServiceReplayExecution(_FrozenStrictModel):
    """Safe projection of one fully reverified sealed passive TCP execution."""

    preparation: NetworkServiceIdentificationPreparation
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    terminal_event: CapabilityDispatchAuditEvent = Field(alias="terminalEvent")
    reconciliation: CapabilityDispatchReconciliation
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    request_reservation_path: _ArtifactPath = Field(alias="requestReservationPath")
    request_reservation_sha256: _Sha256 = Field(alias="requestReservationSha256")
    execution_evidence_path: _ArtifactPath = Field(alias="executionEvidencePath")
    execution_evidence_sha256: _Sha256 = Field(alias="executionEvidenceSha256")
    worker_execution_id: _Identifier = Field(alias="workerExecutionId")
    banner_sha256: _Sha256 = Field(alias="bannerSha256")
    service_name: _ServiceName | None = Field(default=None, alias="serviceName")

    @model_validator(mode="after")
    def bind_execution_projection(self) -> Self:
        prepared = self.preparation.prepared_action
        request = prepared.request
        permit = self.action_permit
        terminal = self.terminal_event
        reconciliation = self.reconciliation
        if (
            self.source_run_id != permit.run_id
            or permit.capability != prepared.capability
            or permit.request_id != request.request_id
            or permit.request_digest != prepared.request_digest
            or permit.normalized_parameters_digest != prepared.normalized_parameters_digest
            or self.approval_receipt.action_permit != permit
            or self.approval_receipt.dispatch_id != permit.dispatch_id
            or terminal.stage is not CapabilityDispatchStage.COMPLETED
            or terminal.permit_id != permit.permit_id
            or terminal.permit_digest != permit.permit_digest
            or terminal.dispatch_id != permit.dispatch_id
            or terminal.run_id != permit.run_id
            or terminal.request_id != permit.request_id
            or terminal.request_digest != permit.request_digest
            or terminal.gateway_execution_id != self.worker_execution_id
            or terminal.evidence != (self.execution_evidence_path,)
            or reconciliation.status is not CapabilityDispatchReconciliationStatus.COMPLETED
            or reconciliation.run_id != permit.run_id
            or reconciliation.permit_id != permit.permit_id
            or reconciliation.permit_digest != permit.permit_digest
            or reconciliation.dispatch_id != permit.dispatch_id
            or reconciliation.terminal_event_digest != terminal.event_digest
            or self.request_reservation_path != f"requests/{permit.request_id}.json"
            or self.execution_evidence_path != f"evidence/{permit.request_id}.json"
        ):
            raise ValueError("NET-001D execution projection differs from sealed authority")
        return self


class NetworkServiceReplayValidation(_FrozenStrictModel):
    """Non-authorizing comparison of source and separately permitted Replay executions."""

    api_version: Literal["pajin.dev/network-service-replay-validation/v1alpha1"] = Field(
        default=NETWORK_SERVICE_REPLAY_VALIDATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkServiceReplayValidation"] = "NetworkServiceReplayValidation"
    validation_id: str = Field(default="", alias="validationId", max_length=110)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_admission: NetworkProtocolKnowledgeAdmission = Field(alias="sourceAdmission")
    source_execution: NetworkServiceReplayExecution = Field(alias="sourceExecution")
    replay_execution: NetworkServiceReplayExecution = Field(alias="replayExecution")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    label_comparison: NetworkProtocolLabelComparison = Field(alias="labelComparison")
    banner_digest_matched: bool = Field(alias="bannerDigestMatched")
    state: _ReplayState
    sealed_source_reverified: Literal[True] = Field(
        default=True,
        alias="sealedSourceReverified",
    )
    sealed_replay_reverified: Literal[True] = Field(
        default=True,
        alias="sealedReplayReverified",
    )
    separate_authorization_verified: Literal[True] = Field(
        default=True,
        alias="separateAuthorizationVerified",
    )
    distinct_worker_execution_verified: Literal[True] = Field(
        default=True,
        alias="distinctWorkerExecutionVerified",
    )
    fresh_connection_session_verified: Literal[True] = Field(
        default=True,
        alias="freshConnectionSessionVerified",
    )
    service_observation_confirmed: Literal[False] = Field(
        default=False,
        alias="serviceObservationConfirmed",
    )
    ground_truth_case_bound: Literal[False] = Field(
        default=False,
        alias="groundTruthCaseBound",
    )
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(*_REPLAY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-001D verified markers must be boolean true")
        return value

    @field_validator("banner_digest_matched", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("NET-001D banner comparison marker must be a boolean")
        return value

    @field_validator(*_REPLAY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-001D Replay authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_replay_validation(self) -> Self:
        _require_network_domain_plan(self.domain_benchmark_plan)
        _require_admission_projection(self.source_admission, self.source_execution)
        _require_equivalent_replay_semantics(self.source_execution, self.replay_execution)
        _require_distinct_replay_authority(self.source_execution, self.replay_execution)
        expected_comparison = _label_comparison(
            self.source_execution.service_name,
            self.replay_execution.service_name,
        )
        expected_state = _comparison_state(expected_comparison)
        if (
            self.label_comparison is not expected_comparison
            or self.state != expected_state
            or self.banner_digest_matched
            is not (self.source_execution.banner_sha256 == self.replay_execution.banner_sha256)
        ):
            raise ValueError("NET-001D neutral Replay comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-service-replay-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"network-service-replay_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("NET-001D Replay validation Digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("NET-001D Replay validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


class NetworkServiceBenchmarkFixtureCase(_FrozenStrictModel):
    """One code-owned synthetic passive banner and its private expected label."""

    fixture_id: _Identifier = Field(alias="fixtureId")
    ground_truth_class: NetworkBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    protocol_profile: Literal["tcp-passive-banner-v1"] = Field(
        default="tcp-passive-banner-v1",
        alias="protocolProfile",
    )
    banner_base64: str = Field(
        alias="bannerBase64",
        max_length=_MAX_BANNER_BASE64_CHARS,
    )
    banner_sha256: _Sha256 = Field(alias="bannerSha256")
    expected_service_name: _ServiceName | None = Field(
        default=None,
        alias="expectedServiceName",
    )
    fixture_materialization: Literal["synthetic-passive-banner"] = Field(
        default="synthetic-passive-banner",
        alias="fixtureMaterialization",
    )
    isolation_requirement: Literal["disposable-loopback-container-per-case"] = Field(
        default="disposable-loopback-container-per-case",
        alias="isolationRequirement",
    )
    application_write_bytes: Literal[0] = Field(
        default=0,
        alias="applicationWriteBytes",
    )

    @model_validator(mode="after")
    def bind_fixture_case(self) -> Self:
        try:
            banner = b64decode(self.banner_base64, validate=True)
        except (BinasciiError, ValueError) as exc:
            raise ValueError("NET-001D fixture banner is not canonical base64") from exc
        if (
            not banner
            or len(banner) > MAX_NETWORK_SERVICE_BANNER_BYTES
            or b64encode(banner).decode("ascii") != self.banner_base64
            or sha256(banner).hexdigest() != self.banner_sha256
            or (self.ground_truth_class is NetworkBenchmarkGroundTruthClass.KNOWN_POSITIVE)
            is not (self.expected_service_name is not None)
        ):
            raise ValueError("NET-001D fixture Ground Truth shape differs")
        return self


class NetworkServiceBenchmarkFixtureProfile(_FrozenStrictModel):
    """Registered isolated-service Ground Truth requirements, never a measurement."""

    api_version: Literal["pajin.dev/network-service-benchmark-fixture-profile/v1alpha1"] = Field(
        default=NETWORK_SERVICE_BENCHMARK_FIXTURE_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkServiceBenchmarkFixtureProfile"] = "NetworkServiceBenchmarkFixtureProfile"
    profile_id: str = Field(default="", alias="profileId", max_length=110)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    protocol_budget: NetworkServiceProtocolBudget = Field(alias="protocolBudget")
    cases: tuple[NetworkServiceBenchmarkFixtureCase, ...] = Field(
        min_length=6,
        max_length=6,
    )
    state: Literal["registered-fixture-ground-truth-not-measured"] = (
        "registered-fixture-ground-truth-not-measured"
    )
    private_ground_truth_verified: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthVerified",
    )
    isolated_fixture_required: Literal[True] = Field(
        default=True,
        alias="isolatedFixtureRequired",
    )
    negative_control_registered: Literal[True] = Field(
        default=True,
        alias="negativeControlRegistered",
    )
    fresh_worker_replay_required: Literal[True] = Field(
        default=True,
        alias="freshWorkerReplayRequired",
    )
    target_profile_selected: Literal[False] = Field(
        default=False,
        alias="targetProfileSelected",
    )
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )
    fixture_execution_authorized: Literal[False] = Field(
        default=False,
        alias="fixtureExecutionAuthorized",
    )
    replay_evidence_bound: Literal[False] = Field(
        default=False,
        alias="replayEvidenceBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    service_observation_confirmed: Literal[False] = Field(
        default=False,
        alias="serviceObservationConfirmed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(*_FIXTURE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-001D fixture requirement markers must be boolean true")
        return value

    @field_validator(*_FIXTURE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-001D fixture authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_fixture_profile(self) -> Self:
        _require_network_domain_plan(self.domain_benchmark_plan)
        if (
            self.protocol_budget != NetworkServiceProtocolBudget()
            or self.cases != _registered_fixture_cases()
        ):
            raise ValueError("NET-001D isolated fixture profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-service-benchmark-fixture-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"network-service-fixtures_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("NET-001D fixture profile Digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("NET-001D fixture profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


def bind_network_service_fresh_worker_replay(
    source_inputs: NetworkServiceObservationSourceInputs,
    source_admission: NetworkProtocolKnowledgeAdmission,
    replay_inputs: NetworkServiceObservationSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    replay_graph_store: SQLiteGraphStore,
) -> NetworkServiceReplayValidation:
    """Reopen two sealed executions and emit one neutral NET-001D comparison."""

    try:
        canonical_admission = NetworkProtocolKnowledgeAdmission.model_validate(
            source_admission.model_dump(mode="json", by_alias=True)
        )
        source = load_verified_network_service_observation_source(
            source_inputs,
            graph_store=source_graph_store,
        )
        replay = load_verified_network_service_observation_source(
            replay_inputs,
            graph_store=replay_graph_store,
        )
        _require_stored_source_admission(canonical_admission, source_graph_store)
        source_projection = _execution_projection(source)
        replay_projection = _execution_projection(replay)
        comparison = _label_comparison(
            source_projection.service_name,
            replay_projection.service_name,
        )
        return NetworkServiceReplayValidation(
            sourceAdmission=canonical_admission,
            sourceExecution=source_projection,
            replayExecution=replay_projection,
            domainBenchmarkPlan=_network_domain_benchmark_plan_ref(),
            labelComparison=comparison,
            bannerDigestMatched=(
                source_projection.banner_sha256 == replay_projection.banner_sha256
            ),
            state=_comparison_state(comparison),
        )
    except NetworkServiceReplayBenchmarkError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise NetworkServiceReplayBenchmarkError(
            "NET-001D fresh Worker execution Replay failed closed"
        ) from exc


def registered_network_service_benchmark_fixture_profile() -> NetworkServiceBenchmarkFixtureProfile:
    """Return the exact six-case isolated fixture Ground Truth without selecting a Target."""

    try:
        return NetworkServiceBenchmarkFixtureProfile(
            domainBenchmarkPlan=_network_domain_benchmark_plan_ref(),
            protocolBudget=NetworkServiceProtocolBudget(),
            cases=_registered_fixture_cases(),
        )
    except (ValidationError, ValueError, RuntimeError) as exc:
        raise NetworkServiceReplayBenchmarkError(
            "NET-001D isolated service fixture registration failed closed"
        ) from exc


def _execution_projection(
    source: VerifiedNetworkServiceObservationSource,
) -> NetworkServiceReplayExecution:
    data = source.evidence.result.data
    banner_sha256 = cast(str, data["bannerSha256"])
    service_name = cast(_ServiceName | None, data.get("serviceName"))
    return NetworkServiceReplayExecution(
        preparation=source.preparation,
        actionPermit=source.permit,
        approvalReceipt=source.approval_receipt,
        terminalEvent=source.terminal,
        reconciliation=source.reconciliation,
        sourceRunId=source.snapshot.verification.run_id,
        sourceRootDigest=source.snapshot.verification.root_digest,
        requestReservationPath=source.reservation_path,
        requestReservationSha256=source.reservation_sha256,
        executionEvidencePath=source.evidence_path,
        executionEvidenceSha256=source.evidence_sha256,
        workerExecutionId=source.evidence.worker_result.execution_id,
        bannerSha256=banner_sha256,
        serviceName=service_name,
    )


def _require_stored_source_admission(
    admission: NetworkProtocolKnowledgeAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    observation = admission.candidate.observation_proposal
    stored_observation = graph_store.event_log.event_for_attempt(
        observation.proposal_id,
        observation.digest(),
    )
    if stored_observation != admission.observation_graph_event:
        raise ValueError("NET-001D source Observation admission is not stored exactly")
    hypothesis = admission.candidate.hypothesis_proposal
    if hypothesis is None:
        if admission.hypothesis_graph_event is not None:
            raise ValueError("NET-001D source Hypothesis admission differs")
        return
    stored_hypothesis = graph_store.event_log.event_for_attempt(
        hypothesis.proposal_id,
        hypothesis.digest(),
    )
    if stored_hypothesis != admission.hypothesis_graph_event:
        raise ValueError("NET-001D source Hypothesis admission is not stored exactly")


def _require_admission_projection(
    admission: NetworkProtocolKnowledgeAdmission,
    execution: NetworkServiceReplayExecution,
) -> None:
    candidate = admission.candidate
    if (
        candidate.preparation != execution.preparation
        or candidate.source_run_id != execution.source_run_id
        or candidate.source_root_digest != execution.source_root_digest
        or candidate.approval_receipt_id != execution.approval_receipt.receipt_id
        or candidate.approval_receipt_digest != execution.approval_receipt.receipt_digest
        or candidate.request_reservation_path != execution.request_reservation_path
        or candidate.request_reservation_sha256 != execution.request_reservation_sha256
        or candidate.execution_evidence_path != execution.execution_evidence_path
        or candidate.execution_evidence_sha256 != execution.execution_evidence_sha256
        or candidate.terminal_event_digest != execution.terminal_event.event_digest
        or candidate.reconciliation_digest != execution.reconciliation.reconciliation_digest
        or candidate.banner_sha256 != execution.banner_sha256
        or candidate.service_name != execution.service_name
    ):
        raise ValueError("NET-001D source admission differs from its sealed execution")


def _require_equivalent_replay_semantics(
    source: NetworkServiceReplayExecution,
    replay: NetworkServiceReplayExecution,
) -> None:
    source_preparation = source.preparation
    replay_preparation = replay.preparation
    source_request = source_preparation.prepared_action.request
    replay_request = replay_preparation.prepared_action.request
    if (
        source_preparation.binding != replay_preparation.binding
        or source_preparation.surface != replay_preparation.surface
        or source_preparation.campaign_scope != replay_preparation.campaign_scope
        or source_preparation.matched_allow_rule != replay_preparation.matched_allow_rule
        or source_preparation.release != replay_preparation.release
        or source_preparation.protocol_budget != replay_preparation.protocol_budget
        or source_preparation.prepared_action.activation_set_digest
        != replay_preparation.prepared_action.activation_set_digest
        or source_preparation.prepared_action.capability
        != replay_preparation.prepared_action.capability
        or source_preparation.prepared_action.normalized_parameters_digest
        != replay_preparation.prepared_action.normalized_parameters_digest
        or source_request.model_dump(mode="json", exclude={"request_id"})
        != replay_request.model_dump(mode="json", exclude={"request_id"})
    ):
        raise ValueError("NET-001D Replay action differs from source protocol semantics")


def _require_distinct_replay_authority(
    source: NetworkServiceReplayExecution,
    replay: NetworkServiceReplayExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(replay)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError("NET-001D Replay reused source execution authority: " + ", ".join(reused))


def _execution_identity_coordinates(
    execution: NetworkServiceReplayExecution,
) -> dict[str, str]:
    permit = execution.action_permit
    receipt = execution.approval_receipt
    terminal = execution.terminal_event
    reconciliation = execution.reconciliation
    return {
        "runId": execution.source_run_id,
        "sourceRootDigest": execution.source_root_digest,
        "requestId": permit.request_id,
        "requestDigest": permit.request_digest,
        "envelopeId": permit.envelope_id,
        "envelopeDigest": permit.envelope_digest,
        "proposalId": permit.proposal_id,
        "proposalDigest": permit.proposal_digest,
        "decisionId": permit.decision_id,
        "decisionDigest": permit.decision_digest,
        "permitId": permit.permit_id,
        "permitDigest": permit.permit_digest,
        "dispatchId": permit.dispatch_id,
        "approvalReceiptId": receipt.receipt_id,
        "approvalReceiptDigest": receipt.receipt_digest,
        "workerExecutionId": execution.worker_execution_id,
        "requestReservationPath": execution.request_reservation_path,
        "requestReservationSha256": execution.request_reservation_sha256,
        "executionEvidencePath": execution.execution_evidence_path,
        "executionEvidenceSha256": execution.execution_evidence_sha256,
        "terminalEventId": terminal.event_id,
        "terminalEventDigest": terminal.event_digest,
        "reconciliationId": reconciliation.reconciliation_id,
        "reconciliationDigest": reconciliation.reconciliation_digest,
    }


def _label_comparison(
    source: _ServiceName | None,
    replay: _ServiceName | None,
) -> NetworkProtocolLabelComparison:
    if source is None and replay is None:
        return NetworkProtocolLabelComparison.UNRESOLVED
    if source is not None and source == replay:
        return NetworkProtocolLabelComparison.MATCHED
    return NetworkProtocolLabelComparison.CHANGED


def _comparison_state(comparison: NetworkProtocolLabelComparison) -> _ReplayState:
    if comparison is NetworkProtocolLabelComparison.MATCHED:
        return "fresh-worker-replay-protocol-label-match"
    if comparison is NetworkProtocolLabelComparison.CHANGED:
        return "fresh-worker-replay-protocol-label-changed"
    return "fresh-worker-replay-protocol-label-unresolved"


def _fixture_case(
    fixture_id: str,
    banner: bytes,
    expected_service_name: _ServiceName | None,
) -> NetworkServiceBenchmarkFixtureCase:
    ground_truth_class = (
        NetworkBenchmarkGroundTruthClass.KNOWN_POSITIVE
        if expected_service_name is not None
        else NetworkBenchmarkGroundTruthClass.NEGATIVE_CONTROL
    )
    return NetworkServiceBenchmarkFixtureCase(
        fixtureId=fixture_id,
        groundTruthClass=ground_truth_class,
        bannerBase64=b64encode(banner).decode("ascii"),
        bannerSha256=sha256(banner).hexdigest(),
        expectedServiceName=expected_service_name,
    )


def _registered_fixture_cases() -> tuple[NetworkServiceBenchmarkFixtureCase, ...]:
    return (
        _fixture_case(
            "network-fixture:ftp-known-positive",
            b"220 PAJIN FTP service ready\r\n",
            "ftp",
        ),
        _fixture_case(
            "network-fixture:imap-known-positive",
            b"* OK PAJIN IMAP4rev1 service ready\r\n",
            "imap",
        ),
        _fixture_case(
            "network-fixture:pop3-known-positive",
            b"+OK PAJIN POP3 service ready\r\n",
            "pop3",
        ),
        _fixture_case(
            "network-fixture:smtp-known-positive",
            b"220 PAJIN ESMTP service ready\r\n",
            "smtp",
        ),
        _fixture_case(
            "network-fixture:ssh-known-positive",
            b"SSH-2.0-PAJINFixture\r\n",
            "ssh",
        ),
        _fixture_case(
            "network-fixture:unknown-negative-control",
            b"PAJIN UNKNOWN PROTOCOL\r\n",
            None,
        ),
    )


def _require_network_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("NET-001D Domain benchmark plan is not registered exactly") from exc
    if (
        plan.domain_classification.domain is not SecurityDomain.NETWORK
        or plan.validation_strategy is not DomainValidationStrategy.FRESH_WORKER_PROTOCOL_REPLAY
    ):
        raise ValueError("NET-001D Domain benchmark strategy differs")


def _network_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.NETWORK:
            return plan.reference()
    raise NetworkServiceReplayBenchmarkError("DOMAIN-006 Network benchmark plan is missing")


__all__ = [
    "NETWORK_SERVICE_BENCHMARK_FIXTURE_PROFILE_API_VERSION",
    "NETWORK_SERVICE_REPLAY_VALIDATION_API_VERSION",
    "NetworkBenchmarkGroundTruthClass",
    "NetworkProtocolLabelComparison",
    "NetworkServiceBenchmarkFixtureCase",
    "NetworkServiceBenchmarkFixtureProfile",
    "NetworkServiceReplayBenchmarkError",
    "NetworkServiceReplayExecution",
    "NetworkServiceReplayValidation",
    "bind_network_service_fresh_worker_replay",
    "registered_network_service_benchmark_fixture_profile",
]
