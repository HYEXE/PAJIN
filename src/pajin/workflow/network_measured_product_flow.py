"""NET-002D sealed read-only product over one exact NET-002C evaluation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import DomainBenchmarkMetricApplicability
from pajin.benchmark.models import benchmark_digest
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.network_fixture_runtime import NetworkFixtureDockerProvider
from pajin.workflow.network_measured_case_authority import (
    NetworkMeasuredCaseAuthorityError,
    NetworkMeasuredCaseMapping,
    NetworkMeasuredCaseRef,
    NetworkValidationFloorPolicyRef,
    registered_network_measured_case_mapping,
    registered_network_validation_floor_policy,
)
from pajin.workflow.network_replay_evaluation import (
    NetworkReplayEvaluationError,
    NetworkReplayEvaluationOutcome,
    NetworkReplayFloorEvaluation,
    NetworkReplayFloorEvaluationRef,
    NetworkReplayMetricObservation,
    load_network_replay_floor_evaluation,
)

NETWORK_MEASURED_PRODUCT_API_VERSION: Literal["pajin.dev/network-measured-product/v1alpha1"] = (
    "pajin.dev/network-measured-product/v1alpha1"
)
NETWORK_MEASURED_PRODUCT_PATH = "network-measured-product.json"

_MAX_PRODUCT_BYTES = 4 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

_EXPECTED_CASE_STATES = (
    "synthetic-known-positive-matched",
    "synthetic-known-positive-matched",
    "synthetic-known-positive-matched",
    "synthetic-known-positive-matched",
    "synthetic-known-positive-matched",
    "synthetic-negative-control-unresolved",
)
_FIXED_RATIONALS = {
    "common.ground-truth-coverage": (6, 6),
    "common.detection-recall": (5, 5),
    "common.false-positive-rate": (0, 1),
    "common.detection-precision": (5, 5),
    "common.replay-or-reanalysis-success-rate": (6, 6),
    "common.total-request-units": (12, 1),
    "common.total-tool-calls": (12, 1),
    "common.evidence-completeness": (144, 144),
    "common.policy-denial-correctness": (5, 5),
    "network.service-identification-accuracy": (6, 6),
}
_SOURCE_TRUE_FIELDS = (
    "source_measurement_reopened",
    "replay_measurement_reopened",
    "source_replay_identity_disjoint",
    "private_ground_truth_evaluated",
    "exact_metric_set_evaluated",
    "cleanup_admission_verified",
    "synthetic_benchmark_only",
    "validation_floor_satisfied",
)
_SOURCE_FALSE_FIELDS = (
    "image_build_authorized",
    "provider_selection_authorized",
    "caller_configuration_authorized",
    "replay_execution_authorized",
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
    "permit_issuance_authorized",
    "additional_execution_authorized",
)
_PRODUCT_FALSE_FIELDS = (
    "raw_banner_included",
    "private_expected_label_included",
    "private_binding_included",
    "source_replay_lineage_included",
    "image_identity_included",
    "runtime_coordinate_included",
    "worker_tool_result_included",
    "graph_included",
    "finding_included",
    "report_included",
    "image_build_authorized",
    "target_creation_authorized",
    "network_creation_authorized",
    "provider_selection_authorized",
    "caller_configuration_authorized",
    "approval_issuance_authorized",
    "action_permit_issuance_authorized",
    "gateway_execution_authorized",
    "worker_execution_authorized",
    "live_measurement_authorized",
    "further_product_projection_authorized",
    "service_confirmation_authorized",
    "graph_admission_authorized",
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
    "general_scanner_authorized",
    "additional_execution_authorized",
    "http_entrypoint_authorized",
)


class NetworkMeasuredProductError(RuntimeError):
    """Raised when a NET-002D product cannot be reproduced exactly."""


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        if set(value.__dict__) - set(type(value).model_fields):
            raise NetworkMeasuredProductError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(getattr(value, field_name), label=label, _seen=seen)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if not isinstance(value, type) and is_dataclass(value):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in fields(value):
            _require_known_instance_fields(getattr(value, item.name), label=label, _seen=seen)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


class NetworkMeasuredProductCase(_FrozenStrictModel):
    """One public case identity and its bounded synthetic comparison state."""

    case: NetworkMeasuredCaseRef
    comparison_state: Literal[
        "synthetic-known-positive-matched",
        "synthetic-negative-control-unresolved",
    ] = Field(alias="comparisonState")


class NetworkMeasuredProductFloor(_FrozenStrictModel):
    """Exact public DOMAIN-006 aggregate values and applicability."""

    evaluation: NetworkReplayFloorEvaluationRef
    policy: NetworkValidationFloorPolicyRef
    observations: tuple[NetworkReplayMetricObservation, ...] = Field(
        min_length=14,
        max_length=14,
    )
    state: Literal["floor-satisfied-independent-fresh-worker-replay"] = (
        "floor-satisfied-independent-fresh-worker-replay"
    )
    required_metric_count: Literal[11] = Field(default=11, alias="requiredMetricCount")
    not_applicable_metric_count: Literal[3] = Field(
        default=3,
        alias="notApplicableMetricCount",
    )
    validation_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="validationFloorSatisfied",
    )
    synthetic_benchmark_only: Literal[True] = Field(
        default=True,
        alias="syntheticBenchmarkOnly",
    )

    @field_validator("observations", mode="before")
    @classmethod
    def canonicalize_json_tuple(cls, value: object, info: ValidationInfo) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @field_validator("validation_floor_satisfied", "synthetic_benchmark_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("NET-002D product floor markers must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_observations(self) -> Self:
        requirements = registered_network_validation_floor_policy().requirements
        if tuple(item.metric for item in self.observations) != tuple(
            item.metric for item in requirements
        ):
            raise ValueError("NET-002D product metric membership or order differs")
        for observation, requirement in zip(self.observations, requirements, strict=True):
            if (
                observation.unit is not requirement.unit
                or observation.applicability is not requirement.applicability
                or observation.comparison is not requirement.comparison
                or observation.not_applicable_reason is not requirement.not_applicable_reason
                or observation.satisfied is not True
            ):
                raise ValueError("NET-002D product metric policy binding differs")
            metric_id = observation.metric.metric_id
            if (
                metric_id in _FIXED_RATIONALS
                and (
                    observation.numerator,
                    observation.denominator,
                )
                != _FIXED_RATIONALS[metric_id]
            ):
                raise ValueError("NET-002D product fixed metric rational differs")
            if metric_id == "common.time-to-first-valid-result" and (
                observation.numerator is None or observation.denominator != 1_000_000
            ):
                raise ValueError("NET-002D product elapsed metric rational differs")
        required = sum(
            item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
            for item in self.observations
        )
        if required != self.required_metric_count or len(self.observations) - required != (
            self.not_applicable_metric_count
        ):
            raise ValueError("NET-002D product metric applicability counts differ")
        return self


class NetworkMeasuredProductAuthorityBoundary(_FrozenStrictModel):
    """Literal disclosure and non-authority ceiling for every NET-002D product."""

    raw_banner_included: Literal[False] = Field(default=False, alias="rawBannerIncluded")
    private_expected_label_included: Literal[False] = Field(
        default=False, alias="privateExpectedLabelIncluded"
    )
    private_binding_included: Literal[False] = Field(default=False, alias="privateBindingIncluded")
    source_replay_lineage_included: Literal[False] = Field(
        default=False, alias="sourceReplayLineageIncluded"
    )
    image_identity_included: Literal[False] = Field(default=False, alias="imageIdentityIncluded")
    runtime_coordinate_included: Literal[False] = Field(
        default=False, alias="runtimeCoordinateIncluded"
    )
    worker_tool_result_included: Literal[False] = Field(
        default=False, alias="workerToolResultIncluded"
    )
    graph_included: Literal[False] = Field(default=False, alias="graphIncluded")
    finding_included: Literal[False] = Field(default=False, alias="findingIncluded")
    report_included: Literal[False] = Field(default=False, alias="reportIncluded")
    image_build_authorized: Literal[False] = Field(default=False, alias="imageBuildAuthorized")
    target_creation_authorized: Literal[False] = Field(
        default=False, alias="targetCreationAuthorized"
    )
    network_creation_authorized: Literal[False] = Field(
        default=False, alias="networkCreationAuthorized"
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False, alias="providerSelectionAuthorized"
    )
    caller_configuration_authorized: Literal[False] = Field(
        default=False, alias="callerConfigurationAuthorized"
    )
    approval_issuance_authorized: Literal[False] = Field(
        default=False, alias="approvalIssuanceAuthorized"
    )
    action_permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="actionPermitIssuanceAuthorized"
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
    further_product_projection_authorized: Literal[False] = Field(
        default=False, alias="furtherProductProjectionAuthorized"
    )
    service_confirmation_authorized: Literal[False] = Field(
        default=False, alias="serviceConfirmationAuthorized"
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthorized"
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
    general_scanner_authorized: Literal[False] = Field(
        default=False, alias="generalScannerAuthorized"
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False, alias="additionalExecutionAuthorized"
    )
    http_entrypoint_authorized: Literal[False] = Field(
        default=False, alias="httpEntrypointAuthorized"
    )

    @field_validator(*_PRODUCT_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("NET-002D product authority markers must be boolean false")
        return value


class NetworkMeasuredProduct(_FrozenStrictModel):
    """Content-addressed public-safe Network measurement product."""

    api_version: Literal["pajin.dev/network-measured-product/v1alpha1"] = Field(
        default=NETWORK_MEASURED_PRODUCT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkMeasuredProduct"] = "NetworkMeasuredProduct"
    product_id: str = Field(default="", alias="productId", max_length=110)
    product_digest: str = Field(default="", alias="productDigest", max_length=64)
    source_evaluation: NetworkReplayFloorEvaluationRef = Field(alias="sourceEvaluation")
    cases: tuple[NetworkMeasuredProductCase, ...] = Field(min_length=6, max_length=6)
    floor: NetworkMeasuredProductFloor
    authority_boundary: NetworkMeasuredProductAuthorityBoundary = Field(alias="authorityBoundary")

    @field_validator("cases", mode="before")
    @classmethod
    def canonicalize_json_cases(cls, value: object, info: ValidationInfo) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @model_validator(mode="after")
    def bind_product(self) -> Self:
        registered = registered_network_measured_case_mapping().public_authority
        expected_cases = tuple(item.reference() for item in registered.public_registry.cases)
        if (
            self.source_evaluation != self.floor.evaluation
            or self.floor.policy != registered.validation_floor_policy.reference()
            or tuple(item.case for item in self.cases) != expected_cases
            or tuple(item.comparison_state for item in self.cases) != _EXPECTED_CASE_STATES
        ):
            raise ValueError("NET-002D product case, floor, or source binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"product_id", "product_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-measured-product/v1",
            material,
            max_bytes=_MAX_PRODUCT_BYTES,
        )
        product_id = f"network-measured-product_{digest}"
        if self.product_digest and self.product_digest != digest:
            raise ValueError("NET-002D product Digest differs")
        if self.product_id and self.product_id != product_id:
            raise ValueError("NET-002D product ID differs")
        object.__setattr__(self, "product_digest", digest)
        object.__setattr__(self, "product_id", product_id)
        return self


@dataclass(frozen=True, slots=True)
class NetworkMeasuredProductSourceReopenContext:
    """Deployment-owned verifier context for one exact NET-002C result."""

    measured_cases: NetworkMeasuredCaseMapping
    provider: NetworkFixtureDockerProvider


@dataclass(frozen=True, slots=True)
class NetworkMeasuredProductOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    product: NetworkMeasuredProduct
    source: NetworkReplayEvaluationOutcome


class NetworkMeasuredProductProjector:
    """Reopen NET-002C and seal only its bounded public product projection."""

    def __init__(self, *, output_root: Path) -> None:
        if not isinstance(output_root, Path):
            raise TypeError("NET-002D product projection requires a Path output root")
        self._output_root = output_root

    def project(
        self,
        source: NetworkReplayEvaluationOutcome,
        *,
        reopen_context: NetworkMeasuredProductSourceReopenContext,
    ) -> NetworkMeasuredProductOutcome:
        try:
            evaluation = _load_source_evaluation(source, reopen_context)
            product = _build_product(evaluation)
            store = RunStore.create(self._output_root, "network-measured-product")
            if store.run_id in _source_run_ids(source):
                raise ValueError("NET-002D product Run reuses a source Run")
            store.append_event(
                "campaign.started",
                {
                    "purpose": "network-measured-product",
                    "sourceEvaluationId": evaluation.evaluation_id,
                },
            )
            artifact_path = store.write_json_create_only(
                NETWORK_MEASURED_PRODUCT_PATH,
                product.model_dump(mode="json", by_alias=True),
            )
            store.append_event(
                "product.network-measured-service-identification.projected",
                _event_payload(artifact_path, product),
            )
            store.append_event("campaign.completed", {"status": "completed"})
            store.seal()
            outcome = NetworkMeasuredProductOutcome(
                run_id=store.run_id,
                run_path=store.path,
                artifact_path=artifact_path,
                product=product.model_copy(deep=True),
                source=source,
            )
            load_network_measured_product(outcome, reopen_context=reopen_context)
            return outcome
        except NetworkMeasuredProductError:
            raise
        except Exception as exc:
            raise NetworkMeasuredProductError("NET-002D product projection failed closed") from exc


def load_network_measured_product(
    outcome: NetworkMeasuredProductOutcome,
    *,
    reopen_context: NetworkMeasuredProductSourceReopenContext,
) -> NetworkMeasuredProduct:
    """Reopen NET-002C first, then rebuild one sealed NET-002D product."""

    if type(outcome) is not NetworkMeasuredProductOutcome:
        raise TypeError("NET-002D reload requires its exact outcome")
    if type(reopen_context) is not NetworkMeasuredProductSourceReopenContext:
        raise TypeError("NET-002D reload requires its exact reopen context")
    try:
        evaluation = _load_source_evaluation(outcome.source, reopen_context)
        if outcome.artifact_path != NETWORK_MEASURED_PRODUCT_PATH:
            raise ValueError("NET-002D product artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={outcome.artifact_path: _MAX_PRODUCT_BYTES},
            expected_run_id=outcome.run_id,
        )
        sealed_bytes = snapshot.artifact_bytes(outcome.artifact_path)
        sealed = NetworkMeasuredProduct.model_validate_json(sealed_bytes)
        rebuilt = _build_product(evaluation)
        if (
            outcome.run_id in _source_run_ids(outcome.source)
            or tuple(item.event_type for item in snapshot.events)
            != (
                "campaign.started",
                "product.network-measured-service-identification.projected",
                "campaign.completed",
            )
            or sealed != outcome.product
            or sealed != rebuilt
            or sealed_bytes != _strict_json_bytes(sealed.model_dump(mode="json", by_alias=True))
            or snapshot.events[0].payload
            != {
                "purpose": "network-measured-product",
                "sourceEvaluationId": evaluation.evaluation_id,
            }
            or snapshot.events[1].payload != _event_payload(outcome.artifact_path, sealed)
            or snapshot.events[2].payload != {"status": "completed"}
        ):
            raise ValueError("NET-002D product publication differs")
        return sealed.model_copy(deep=True)
    except NetworkMeasuredProductError:
        raise
    except (
        AttributeError,
        NetworkMeasuredCaseAuthorityError,
        NetworkReplayEvaluationError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise NetworkMeasuredProductError(
            "NET-002D product is not sealed and reproducible"
        ) from exc


def _load_source_evaluation(
    source: NetworkReplayEvaluationOutcome,
    context: NetworkMeasuredProductSourceReopenContext,
) -> NetworkReplayFloorEvaluation:
    if type(source) is not NetworkReplayEvaluationOutcome:
        raise TypeError("NET-002D product requires one exact NET-002C outcome")
    if type(context) is not NetworkMeasuredProductSourceReopenContext:
        raise TypeError("NET-002D product requires one exact reopen context")
    return load_network_replay_floor_evaluation(
        source,
        measured_cases=context.measured_cases,
        provider=context.provider,
    )


def _build_product(evaluation: NetworkReplayFloorEvaluation) -> NetworkMeasuredProduct:
    if (
        any(getattr(evaluation, field) is not True for field in _SOURCE_TRUE_FIELDS)
        or any(getattr(evaluation, field) is not False for field in _SOURCE_FALSE_FIELDS)
        or evaluation.state != "floor-satisfied-independent-fresh-worker-replay"
        or len(evaluation.cases) != 6
        or len(evaluation.observations) != 14
    ):
        raise ValueError("NET-002D source evaluation authority ceiling differs")
    observations = tuple(
        NetworkReplayMetricObservation.model_validate_json(item.model_dump_json(by_alias=True))
        for item in evaluation.observations
    )
    return NetworkMeasuredProduct(
        sourceEvaluation=evaluation.reference(),
        cases=tuple(
            NetworkMeasuredProductCase(
                case=item.case,
                comparisonState=item.comparison_state,
            )
            for item in evaluation.cases
        ),
        floor=NetworkMeasuredProductFloor(
            evaluation=evaluation.reference(),
            policy=evaluation.floor_policy,
            observations=observations,
        ),
        authorityBoundary=NetworkMeasuredProductAuthorityBoundary(),
    )


def _source_run_ids(source: NetworkReplayEvaluationOutcome) -> frozenset[str]:
    return frozenset((source.run_id, source.source.run_id, source.replay.run_id))


def _event_payload(artifact_path: str, product: NetworkMeasuredProduct) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "productId": product.product_id,
        "productDigest": product.product_digest,
        "sourceEvaluationId": product.source_evaluation.evaluation_id,
        "sourceEvaluationDigest": product.source_evaluation.evaluation_digest,
        "caseCount": len(product.cases),
        "metricCount": len(product.floor.observations),
        "floorSatisfied": product.floor.validation_floor_satisfied,
        "serviceConfirmationAuthorized": (
            product.authority_boundary.service_confirmation_authorized
        ),
        "additionalExecutionAuthorized": (
            product.authority_boundary.additional_execution_authorized
        ),
    }


def _strict_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


__all__ = [
    "NETWORK_MEASURED_PRODUCT_API_VERSION",
    "NETWORK_MEASURED_PRODUCT_PATH",
    "NetworkMeasuredProduct",
    "NetworkMeasuredProductAuthorityBoundary",
    "NetworkMeasuredProductCase",
    "NetworkMeasuredProductError",
    "NetworkMeasuredProductFloor",
    "NetworkMeasuredProductOutcome",
    "NetworkMeasuredProductProjector",
    "NetworkMeasuredProductSourceReopenContext",
    "load_network_measured_product",
]
